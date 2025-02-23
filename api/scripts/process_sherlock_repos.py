from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from functools import partial
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
import concurrent.futures
import hashlib
import json
import logging
import re
import shutil
import tempfile
import time
import warnings
from dotenv import load_dotenv
import requests
import tqdm
import os
import sys

# Add the api directory to the Python path
api_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(api_dir)

# Now import the services after adding to Python path
from services.embedding_processor import EmbeddingProcessor
from services.github_repo_manager import GithubRepoManager
from services.solidity_analyzer import analyze_solidity_files

# Set tokenizers parallelism to avoid deadlock warnings
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%H:%M:%S'
)

# Suppress specific loggers
logging.getLogger('sentence_transformers').setLevel(logging.ERROR)
logging.getLogger('transformers').setLevel(logging.ERROR)
logging.getLogger('filelock').setLevel(logging.ERROR)
logging.getLogger('torch').setLevel(logging.ERROR)
logging.getLogger('huggingface_hub').setLevel(logging.ERROR)

# Suppress all warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Constants
CACHE_DIR = Path(".cache")
BATCH_SIZE = 100  # Increased batch size for better throughput
MAX_WORKERS = min(32, (cpu_count() * 2))  # Optimal number of workers
CHUNK_SIZE = 2000  # Reduced chunk size for faster processing
EMBEDDING_BATCH_SIZE = 50  # Number of items to process in parallel for embeddings
PROGRESS_FILE = Path("processing_progress.json")
REPOS_PER_BATCH = 5  # Number of repositories to process in one run


def setup_cache():
    """Setup cache directory for processed files"""
    CACHE_DIR.mkdir(exist_ok=True)
    return CACHE_DIR


def get_cache_key(content: str) -> str:
    """Generate a cache key for file content"""
    return hashlib.sha256(content.encode()).hexdigest()


def load_from_cache(cache_key: str) -> Optional[Dict]:
    """Load processed results from cache"""
    cache_file = CACHE_DIR / f"{cache_key}.json"
    if cache_file.exists():
        try:
            with cache_file.open('r') as f:
                return json.load(f)
        except:
            return None
    return None


def save_to_cache(cache_key: str, data: Dict):
    """Save processed results to cache"""
    cache_file = CACHE_DIR / f"{cache_key}.json"
    with cache_file.open('w') as f:
        json.dump(data, f)


def extract_code_references(content: str) -> List[Dict]:
    """Extract code references and snippets from markdown content"""
    references = []

    # Patterns for code references
    patterns = [
        # GitHub links
        r'https://github\.com/[^/]+/[^/]+/blob/[^/]+/(.+?)#L(\d+)(?:-L(\d+))?',
        # Inline code references
        r'`([^`]+?\.sol)(?::(\d+)(?:-(\d+))?)?`',
        # Code blocks with file references
        r'```[^\n]*\n.*?```\s*(?:File|Source):\s*`?([^`\n]+\.sol)`?(?:[^\n]*?(?:line|L):?\s*(\d+)(?:\s*-\s*L?(\d+))?)?'
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, content, re.DOTALL | re.IGNORECASE):
            file_path = match.group(1)
            start_line = int(match.group(2)) if match.group(2) else None
            end_line = int(match.group(3)) if match.group(3) else start_line

            if file_path.endswith('.sol'):
                references.append({
                    'file_path': file_path,
                    'start_line': start_line,
                    'end_line': end_line,
                    # Add context
                    'context': content[max(0, match.start() - 100):match.start()]
                })

    return references


def truncate_metadata(metadata: Dict, max_bytes: int = 40000) -> Dict:
    """Truncate metadata fields to stay within Pinecone's size limit"""
    def get_size(obj: Any) -> int:
        return len(json.dumps(obj).encode('utf-8'))

    def truncate_string(s: str, max_len: int) -> str:
        while len(s.encode('utf-8')) > max_len:
            s = s[:-1]
        return s

    result = {}
    current_size = 0

    # Priority fields that should not be truncated
    priority_fields = {'type', 'repo_name',
                       'file_path', 'severity', 'category'}

    # First, add priority fields
    for key in priority_fields:
        if key in metadata:
            value = metadata[key]
            size = get_size({key: value})
            if current_size + size <= max_bytes:
                result[key] = value
                current_size += size

    # Then handle other fields with size limits
    remaining_bytes = max_bytes - current_size
    per_field_limit = remaining_bytes // (len(metadata) - len(result))

    for key, value in metadata.items():
        if key in result:
            continue

        if isinstance(value, str):
            value = truncate_string(value, per_field_limit)
        elif isinstance(value, (list, dict)):
            # Convert complex objects to string representation
            value = str(value)
            value = truncate_string(value, per_field_limit)

        field_size = get_size({key: value})
        if current_size + field_size <= max_bytes:
            result[key] = value
            current_size += field_size

    return result


def chunk_content(content: str, max_tokens: int = 4000) -> List[str]:
    """Split content into chunks that fit within token limits"""
    # Rough estimate: 1 token ≈ 4 characters for English text
    chars_per_chunk = max_tokens * 4

    # Split into paragraphs first
    paragraphs = content.split('\n\n')

    chunks = []
    current_chunk = []
    current_length = 0

    for para in paragraphs:
        para_length = len(para)

        if current_length + para_length > chars_per_chunk:
            if current_chunk:
                chunks.append('\n\n'.join(current_chunk))
                current_chunk = []
                current_length = 0

            # If paragraph itself is too long, split it
            if para_length > chars_per_chunk:
                words = para.split()
                temp_chunk = []
                temp_length = 0

                for word in words:
                    word_length = len(word) + 1  # +1 for space
                    if temp_length + word_length > chars_per_chunk:
                        chunks.append(' '.join(temp_chunk))
                        temp_chunk = [word]
                        temp_length = word_length
                    else:
                        temp_chunk.append(word)
                        temp_length += word_length

                if temp_chunk:
                    current_chunk = temp_chunk
                    current_length = temp_length
            else:
                current_chunk = [para]
                current_length = para_length
        else:
            current_chunk.append(para)
            current_length += para_length

    if current_chunk:
        chunks.append('\n\n'.join(current_chunk))

    return chunks


def process_solidity_file(file_data: Dict, embedding_processor: EmbeddingProcessor) -> List[Dict]:
    """Process a single Solidity file with caching"""
    cache_key = get_cache_key(file_data['content'])
    cached_result = load_from_cache(cache_key)

    if cached_result:
        return cached_result

    # Split content into manageable chunks if needed
    content_chunks = chunk_content(file_data['content'])
    all_embeddings = []

    for chunk_idx, chunk in enumerate(content_chunks):
        chunk_data = {
            **file_data,
            'content': chunk,
            'chunk_index': chunk_idx,
            'total_chunks': len(content_chunks)
        }

        # Generate embeddings for the chunk
        embeddings = embedding_processor.process_solidity_file(chunk_data)

        # Process each embedding
        for embedding in embeddings:
            if 'metadata' in embedding:
                embedding['metadata'] = truncate_metadata(
                    embedding['metadata'])
            all_embeddings.append(embedding)

    if all_embeddings:
        save_to_cache(cache_key, all_embeddings)

    return all_embeddings


def process_chunk_with_timeout(chunk_data: Dict, embedding_processor: EmbeddingProcessor, chunk_idx: int, total_chunks: int) -> List[Dict]:
    """Process a single chunk with timeout"""
    try:
        logger.info(f"Processing chunk {chunk_idx + 1}/{total_chunks}")
        logger.info(f"Generating embeddings for chunk {chunk_idx + 1}...")

        # Set a timeout for the embedding generation
        start_time = time.time()
        embeddings = []

        try:
            embeddings = embedding_processor.process_vulnerability_report(
                chunk_data,
                repo_path=None
            )
        except Exception as e:
            logger.error(
                f"Error generating embeddings for chunk {chunk_idx + 1}: {str(e)}")
            return []

        processing_time = time.time() - start_time
        logger.info(
            f"Generated {len(embeddings) if embeddings else 0} embeddings for chunk {chunk_idx + 1} in {processing_time:.2f}s")

        return embeddings
    except Exception as e:
        logger.error(f"Error in chunk processing: {str(e)}")
        return []


def process_files_batch(files: List[Dict], embedding_processor: EmbeddingProcessor) -> List[Dict]:
    """Process a batch of files in parallel with improved caching"""
    embeddings = []
    cached_files = []
    uncached_files = []

    # First check cache for all files
    for file_data in files:
        cache_key = get_cache_key(file_data['content'])
        cached_result = load_from_cache(cache_key)
        if cached_result:
            embeddings.extend(cached_result)
            cached_files.append(file_data['file_path'])
        else:
            uncached_files.append((cache_key, file_data))

    if cached_files:
        logger.info(f"Found {len(cached_files)} files in cache")

    if uncached_files:
        logger.info(f"Processing {len(uncached_files)} uncached files")
        # Process uncached files in parallel
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {}
            for cache_key, file_data in uncached_files:
                future = executor.submit(
                    process_single_file, file_data, embedding_processor)
                future_to_file[future] = (cache_key, file_data)

            for future in as_completed(future_to_file):
                cache_key, file_data = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        embeddings.extend(result)
                        save_to_cache(cache_key, result)
                except Exception as e:
                    logger.error(
                        f"Error processing {file_data['file_path']}: {str(e)}")

    return embeddings


def process_single_file(file_data: Dict, embedding_processor: EmbeddingProcessor) -> List[Dict]:
    """Process a single file with optimized chunking"""
    try:
        # Split content into smaller chunks for faster processing
        content_chunks = chunk_content(
            file_data['content'], max_tokens=CHUNK_SIZE)
        chunk_embeddings = []

        for chunk_idx, chunk in enumerate(content_chunks):
            chunk_data = {
                **file_data,
                'content': chunk,
                'chunk_index': chunk_idx,
                'total_chunks': len(content_chunks)
            }

            # Generate embeddings for the chunk
            embeddings = embedding_processor.process_solidity_file(chunk_data)
            if embeddings:
                chunk_embeddings.extend(embeddings)

        return chunk_embeddings
    except Exception as e:
        logger.error(
            f"Error in process_single_file for {file_data['file_path']}: {str(e)}")
        return []


def process_vulnerability_report(report_data: Dict, solidity_files: List[Dict], embedding_processor: EmbeddingProcessor) -> Tuple[List[Dict], Optional[str]]:
    """Process a vulnerability report with optimized parallel processing"""
    try:
        start_time = time.time()

        # Extract code references with timeout
        code_refs = extract_code_references(report_data['content'])

        # Match code references with actual files in parallel
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for ref in code_refs:
                futures.append(executor.submit(
                    match_code_reference, ref, solidity_files))

            matched_refs = []
            for future in as_completed(futures):
                result = future.result()
                if result:
                    matched_refs.append(result)

        # Split content into smaller chunks with optimized size
        content_chunks = chunk_content(
            report_data['content'], max_tokens=CHUNK_SIZE)

        all_embeddings = []
        chunk_futures = []

        # Process chunks in parallel with individual timeouts
        with ThreadPoolExecutor(max_workers=min(4, len(content_chunks))) as chunk_executor:
            for chunk_idx, chunk in enumerate(content_chunks):
                if time.time() - start_time > 300:  # 5 minute total timeout
                    break

                chunk_data = {
                    **report_data,
                    'content': chunk[:CHUNK_SIZE],
                    'chunk_index': chunk_idx,
                    'total_chunks': len(content_chunks),
                    'matched_refs': matched_refs
                }

                future = chunk_executor.submit(
                    process_chunk_with_timeout,
                    chunk_data,
                    embedding_processor,
                    chunk_idx,
                    len(content_chunks)
                )
                chunk_futures.append(future)

            # Process completed chunks as they finish
            for future in as_completed(chunk_futures):
                try:
                    chunk_embeddings = future.result(timeout=120)
                    if chunk_embeddings:
                        all_embeddings.extend(chunk_embeddings)
                except TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error processing chunk: {str(e)}")
                    continue

        if not all_embeddings:
            return [], "No valid embeddings generated"

        return all_embeddings, None

    except Exception as e:
        error_msg = f"Error processing report {report_data['report_file']}: {str(e)}"
        logger.error(error_msg)
        return [], error_msg


def match_code_reference(ref: Dict, solidity_files: List[Dict]) -> Optional[Dict]:
    """Match a code reference with actual files"""
    try:
        for sol_file in solidity_files:
            if sol_file['file_path'].endswith(ref['file_path']):
                ref['actual_file'] = sol_file
                return ref
    except Exception:
        return None
    return None


def process_repository_pair(repo_name: str, embedding_processor: EmbeddingProcessor, github_manager: GithubRepoManager) -> None:
    """Process a repository pair with optimized batching and caching"""
    logger.info(
        f"\n{'='*80}\nStarting processing of repository: {repo_name}\n{'='*80}")

    if embedding_processor.is_repository_processed(repo_name):
        logger.info(f"Repository {repo_name} already processed, skipping...")
        return

    temp_dir = tempfile.mkdtemp()
    try:
        # Process main repository
        main_repo_url = f"https://github.com/sherlock-audit/{repo_name}"
        main_repo_dir = os.path.join(temp_dir, 'codebase')
        os.makedirs(main_repo_dir, exist_ok=True)

        logger.info(f"Cloning main repository: {main_repo_url}")

        main_repo_info = {
            "name": repo_name,
            "clone_url": main_repo_url,
            "is_judging": False
        }

        if github_manager.clone_repository(main_repo_info, main_repo_dir):
            # Collect all Solidity files first
            solidity_files = []
            logger.info("Collecting Solidity files...")
            for item in github_manager.process_repository_content(main_repo_info, main_repo_dir):
                if item["type"] == "solidity_file":
                    try:
                        file_path = os.path.join(
                            main_repo_dir, item["file_path"])
                        logger.info(
                            f"Processing Solidity file: {item['file_path']}")
                        with open(file_path, 'r') as f:
                            content = f.read()
                            solidity_files.append({
                                "content": content[:50000],  # Limit file size
                                "repo_name": repo_name,
                                "file_path": item["file_path"],
                                "directory": os.path.dirname(item["file_path"])
                            })
                    except Exception as e:
                        logger.error(
                            f"Error reading Solidity file {item['file_path']}: {str(e)}")
                        continue

            # Process Solidity files in batches
            total_batches = (len(solidity_files) +
                             BATCH_SIZE - 1) // BATCH_SIZE
            logger.info(
                f"Processing {len(solidity_files)} Solidity files in {total_batches} batches")

            for i in range(0, len(solidity_files), BATCH_SIZE):
                batch = solidity_files[i:i + BATCH_SIZE]
                batch_num = i//BATCH_SIZE + 1
                try:
                    logger.info(
                        f"\nProcessing batch {batch_num}/{total_batches}")
                    logger.info("Files in this batch:")
                    for file in batch:
                        logger.info(f"  - {file['file_path']}")

                    embeddings = process_files_batch(
                        batch, embedding_processor)
                    if embeddings:
                        logger.info(
                            f"Storing {len(embeddings)} embeddings for batch {batch_num}")
                        embedding_processor.store_embeddings(embeddings)
                except Exception as e:
                    logger.error(
                        f"Error processing batch {batch_num}: {str(e)}")
                    continue

            # Process judging repository
            judging_repo_name = f"{repo_name}-judging"
            judging_repo_url = f"https://github.com/sherlock-audit/{judging_repo_name}"
            judging_repo_dir = os.path.join(temp_dir, 'judging')
            os.makedirs(judging_repo_dir, exist_ok=True)

            logger.info(
                f"\nProcessing judging repository: {judging_repo_name}")

            judging_repo_info = {
                "name": judging_repo_name,
                "clone_url": judging_repo_url,
                "is_judging": True
            }

            if github_manager.clone_repository(judging_repo_info, judging_repo_dir):
                # Process vulnerability reports with context from Solidity files
                vulnerability_reports = []
                logger.info("Collecting vulnerability reports...")
                for item in github_manager.process_repository_content(judging_repo_info, judging_repo_dir):
                    if item["type"] == "vulnerability_report":
                        try:
                            report_path = os.path.join(
                                judging_repo_dir, item["report_file"])
                            with open(report_path, 'r') as f:
                                content = f.read()
                                vulnerability_reports.append({
                                    # Limit report size
                                    "content": content[:100000],
                                    "repo_name": judging_repo_name,
                                    "report_file": item["report_file"]
                                })
                                logger.info(
                                    f"Added report: {item['report_file']}")
                        except Exception as e:
                            logger.error(
                                f"Error reading report {item['report_file']}: {str(e)}")
                            continue

                logger.info(
                    f"Found {len(vulnerability_reports)} vulnerability reports")

                # Process vulnerability reports with timeout and progress tracking
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    future_to_report = {
                        executor.submit(
                            process_vulnerability_report,
                            report,
                            solidity_files,
                            embedding_processor
                        ): report for report in vulnerability_reports
                    }

                    with tqdm.tqdm(total=len(vulnerability_reports), desc=f"Processing reports for {repo_name}") as pbar:
                        for future in concurrent.futures.as_completed(future_to_report):
                            report = future_to_report[future]
                            try:
                                logger.info(
                                    f"\nProcessing report: {report['report_file']}")
                                embeddings, error = future.result(
                                    timeout=600)  # 10 minute timeout per report
                                if error:
                                    logger.error(
                                        f"Error processing {report['report_file']}: {error}")
                                elif embeddings:
                                    try:
                                        logger.info(
                                            f"Storing {len(embeddings)} embeddings for {report['report_file']}")
                                        embedding_processor.store_embeddings(
                                            embeddings)
                                    except Exception as store_error:
                                        logger.error(
                                            f"Error storing embeddings: {str(store_error)}")
                            except TimeoutError:
                                logger.error(
                                    f"Timeout processing report {report['report_file']}")
                            except Exception as e:
                                logger.error(
                                    f"Error processing report {report['report_file']}: {str(e)}")
                            finally:
                                pbar.update(1)

        # Track successful processing
        embedding_processor.track_processed_repository(repo_name, "completed", {
            "main_repo_url": main_repo_url,
            "judging_repo_url": judging_repo_url,
            "processed_files_count": len(solidity_files)
        })
        logger.info(
            f"\n{'='*80}\nSuccessfully completed processing repository: {repo_name}\n{'='*80}")

    except Exception as e:
        logger.error(f"Error processing repository {repo_name}: {str(e)}")
        embedding_processor.track_processed_repository(repo_name, "error", {
            "error": str(e)
        })
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def get_sherlock_repositories() -> List[Dict]:
    """
    Get list of repositories from Sherlock's GitHub organization
    """
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        raise ValueError("GITHUB_TOKEN environment variable is not set")

    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    repos = []
    page = 1
    while True:
        response = requests.get(
            f'https://api.github.com/orgs/sherlock-audit/repos?page={page}&per_page=100',
            headers=headers
        )
        if response.status_code != 200:
            raise Exception(f"Failed to fetch repositories: {response.text}")

        page_repos = response.json()
        if not page_repos:
            break

        repos.extend(page_repos)
        page += 1

    return repos


def load_progress() -> Dict:
    """Load processing progress from file"""
    if PROGRESS_FILE.exists():
        try:
            with PROGRESS_FILE.open('r') as f:
                return json.load(f)
        except:
            return {"processed": [], "failed": [], "current_batch": 0}
    return {"processed": [], "failed": [], "current_batch": 0}


def save_progress(progress: Dict):
    """Save processing progress to file"""
    with PROGRESS_FILE.open('w') as f:
        json.dump(progress, f, indent=2)


def get_next_batch_repos(all_repos: List[str], progress: Dict) -> List[str]:
    """Get the next batch of repositories to process"""
    processed = set(progress["processed"] + progress["failed"])
    remaining = [repo for repo in all_repos if repo not in processed]
    return remaining[:REPOS_PER_BATCH]


def main():
    """Main function to process repositories"""
    # Check if just showing progress
    if len(sys.argv) > 1 and sys.argv[1] == "--show-progress":
        progress = load_progress()
        logger.info("\nCurrent Progress:")
        logger.info(
            f"Total repositories processed: {len(progress['processed'])}")
        logger.info(f"Total repositories failed: {len(progress['failed'])}")

        if progress['processed']:
            logger.info("\nProcessed repositories:")
            for repo in progress['processed']:
                logger.info(f"  ✓ {repo}")

        if progress['failed']:
            logger.info("\nFailed repositories:")
            for repo in progress['failed']:
                logger.info(f"  ✗ {repo}")

        return

    # Initialize services
    pinecone_api_key = os.getenv('PINECONE_API_KEY')
    github_token = os.getenv('GITHUB_TOKEN')

    if not all([pinecone_api_key, github_token]):
        raise ValueError("Required environment variables are not set")

    # Setup cache
    setup_cache()

    embedding_processor = EmbeddingProcessor(
        pinecone_api_key,
        "us-east-1-aws",
        'smartsmart'
    )
    github_manager = GithubRepoManager(github_token)

    # Load progress
    progress = load_progress()
    logger.info(
        f"Loaded progress: {len(progress['processed'])} repositories processed, {len(progress['failed'])} failed")

    # Get repositories to process
    if len(sys.argv) > 1:
        # Process specific repositories if provided
        all_repos = [repo.replace('-judging', '') for repo in sys.argv[1:]]
        all_repos = list(set(all_repos))  # Remove duplicates
    else:
        # Get all repositories
        repos = get_sherlock_repositories()
        all_repos = [repo['name']
                     for repo in repos if not repo['name'].endswith('-judging')]
        all_repos = list(set(all_repos))  # Remove duplicates

    # Get next batch of repositories
    batch_repos = get_next_batch_repos(all_repos, progress)

    if not batch_repos:
        logger.info("No more repositories to process!")
        return

    logger.info(
        f"\n{'='*80}\nProcessing batch of {len(batch_repos)} repositories:\n{', '.join(batch_repos)}\n{'='*80}")

    # Process repositories in the current batch
    for repo_name in batch_repos:
        try:
            process_repository_pair(
                repo_name, embedding_processor, github_manager)
            progress["processed"].append(repo_name)
            save_progress(progress)
        except Exception as e:
            logger.error(f"Failed to process repository {repo_name}: {str(e)}")
            progress["failed"].append(repo_name)
            save_progress(progress)

    # Print summary
    logger.info("\nBatch Processing Summary:")
    logger.info(f"Total repositories in this batch: {len(batch_repos)}")
    logger.info(
        f"Successfully processed: {len([r for r in batch_repos if r in progress['processed']])}")
    logger.info(
        f"Failed to process: {len([r for r in batch_repos if r in progress['failed']])}")

    # Print overall progress
    logger.info("\nOverall Progress:")
    logger.info(
        f"Total repositories processed so far: {len(progress['processed'])}")
    logger.info(f"Total repositories failed so far: {len(progress['failed'])}")
    remaining = len(all_repos) - \
        len(progress["processed"]) - len(progress["failed"])
    logger.info(f"Remaining repositories: {remaining}")

    if remaining > 0:
        logger.info("\nNext batch will process these repositories:")
        next_batch = get_next_batch_repos(all_repos, progress)
        for repo in next_batch:
            logger.info(f"  - {repo}")


if __name__ == "__main__":
    main()
