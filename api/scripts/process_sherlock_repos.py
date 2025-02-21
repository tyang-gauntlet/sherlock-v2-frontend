from services.github_repo_manager import GithubRepoManager
from services.embedding_processor import EmbeddingProcessor
import os
import sys
from dotenv import load_dotenv
from typing import List, Dict, Tuple, Optional
import requests
import tempfile
import shutil
import logging
from multiprocessing import Pool, cpu_count
from functools import partial
import tqdm
import warnings

# Add the api directory to the Python path
api_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(api_dir)

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


def create_embedding_processor():
    """Create a new embedding processor instance for each process"""
    pinecone_api_key = os.getenv('PINECONE_API_KEY')
    return EmbeddingProcessor(
        pinecone_api_key,
        "us-east-1-aws",
        'smartsmart'
    )


def process_vulnerability_report(args: Tuple[Dict, str]) -> Tuple[List[Dict], Optional[str]]:
    """Process a single vulnerability report with its own embedding processor"""
    report_data, main_repo_dir = args
    try:
        # Create a new embedding processor for this process
        embedding_processor = create_embedding_processor()

        embeddings = embedding_processor.process_vulnerability_report(
            report_data,
            repo_path=main_repo_dir
        )
        if embeddings:
            embedding_processor.store_embeddings(embeddings)
            return embeddings, None
        return [], None
    except Exception as e:
        error_msg = f"Error processing report {report_data['report_file']}: {str(e)}"
        return [], error_msg


def process_repository_pair(repo_name: str, embedding_processor: EmbeddingProcessor, github_manager: GithubRepoManager) -> None:
    """Process a repository and its corresponding judging repository"""
    base_url = "https://github.com/sherlock-audit"

    # Check if already processed
    if embedding_processor.is_repository_processed(repo_name):
        logger.info(f"Repository {repo_name} already processed, skipping...")
        return

    temp_dir = tempfile.mkdtemp()
    errors = []
    try:
        # Process main repository
        main_repo_url = f"{base_url}/{repo_name}"
        main_repo_dir = os.path.join(temp_dir, 'codebase')
        os.makedirs(main_repo_dir, exist_ok=True)

        logger.info(f"Processing main repository: {repo_name}")
        main_repo_info = {
            "name": repo_name,
            "clone_url": main_repo_url,
            "is_judging": False
        }

        if github_manager.clone_repository(main_repo_info, main_repo_dir):
            # Process Solidity files
            solidity_files = []
            for item in github_manager.process_repository_content(main_repo_info, main_repo_dir):
                if item["type"] == "solidity_file":
                    solidity_files.append(item)

            logger.info(f"Found {len(solidity_files)} Solidity files")
            with tqdm.tqdm(total=len(solidity_files), desc="Processing Solidity files", unit="file") as pbar:
                for item in solidity_files:
                    with open(os.path.join(main_repo_dir, item["file_path"]), 'r') as f:
                        content = f.read()
                        file_data = {
                            "content": content,
                            "repo_name": repo_name,
                            "file_path": item["file_path"],
                            "directory": os.path.dirname(item["file_path"])
                        }
                        embeddings = embedding_processor.process_solidity_file(
                            file_data)
                        if embeddings:
                            embedding_processor.store_embeddings(embeddings)
                        pbar.update(1)

        # Process judging repository
        judging_repo_name = f"{repo_name}-judging"  # Only add -judging once
        judging_repo_url = f"{base_url}/{judging_repo_name}"
        judging_repo_dir = os.path.join(temp_dir, 'judging')
        os.makedirs(judging_repo_dir, exist_ok=True)

        logger.info(f"Processing judging repository: {judging_repo_name}")
        judging_repo_info = {
            "name": judging_repo_name,
            "clone_url": judging_repo_url,
            "is_judging": True
        }

        if github_manager.clone_repository(judging_repo_info, judging_repo_dir):
            # Collect all vulnerability reports first
            vulnerability_reports = []
            for item in github_manager.process_repository_content(judging_repo_info, judging_repo_dir):
                if item["type"] == "vulnerability_report":
                    report_path = os.path.join(
                        judging_repo_dir, item["report_file"])
                    with open(report_path, 'r') as f:
                        content = f.read()
                        report_data = {
                            "content": content,
                            "repo_name": judging_repo_name,
                            "report_file": item["report_file"]
                        }
                        vulnerability_reports.append(report_data)

            # Process vulnerability reports in parallel
            num_processes = min(cpu_count(), 8)  # Use up to 8 processes
            logger.info(
                f"Processing {len(vulnerability_reports)} vulnerability reports using {num_processes} processes")

            # Process reports in parallel with progress bar
            with Pool(num_processes) as pool:
                with tqdm.tqdm(total=len(vulnerability_reports), desc="Processing reports", unit="report", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]') as pbar:
                    for embeddings, error in pool.imap(process_vulnerability_report, [(report, main_repo_dir) for report in vulnerability_reports]):
                        if error:
                            errors.append(error)
                        if embeddings:
                            embedding_processor.store_embeddings(embeddings)
                        pbar.update(1)

        # Track successful processing
        embedding_processor.track_processed_repository(repo_name, "completed", {
            "main_repo_url": main_repo_url,
            "judging_repo_url": judging_repo_url,
            "processed_files_count": len(list(github_manager.process_repository_content(main_repo_info, main_repo_dir)))
        })
        logger.info(f"Successfully processed repository pair: {repo_name}")

        # Print errors if any occurred
        if errors:
            logger.info("\nErrors encountered during processing:")
            for error in errors:
                logger.info(f"- {error}")

    except Exception as e:
        logger.error(f"Error processing repository {repo_name}: {str(e)}")
        embedding_processor.track_processed_repository(repo_name, "error", {
            "error": str(e)
        })
    finally:
        # Clean up
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def reset_repositories(repo_names: List[str], embedding_processor: EmbeddingProcessor) -> None:
    """Reset specified repositories by deleting their entries from Pinecone"""
    for repo_name in repo_names:
        try:
            logger.info(f"Resetting repository: {repo_name}")
            embedding_processor.delete_repository(repo_name)
            # Also delete the judging repository
            embedding_processor.delete_repository(f"{repo_name}-judging")
        except Exception as e:
            logger.error(f"Error resetting repository {repo_name}: {str(e)}")


def main():
    """Main function to process repositories"""
    # Initialize services
    pinecone_api_key = os.getenv('PINECONE_API_KEY')
    github_token = os.getenv('GITHUB_TOKEN')

    if not all([pinecone_api_key, github_token]):
        raise ValueError("Required environment variables are not set")

    embedding_processor = EmbeddingProcessor(
        pinecone_api_key,
        "us-east-1-aws",
        'smartsmart'
    )
    github_manager = GithubRepoManager(github_token)

    # Process specific repositories if provided
    if len(sys.argv) > 1:
        repos_to_process = []
        for repo in sys.argv[1:]:
            # Remove -judging suffix if present to get base name
            base_repo = repo.replace('-judging', '')
            if base_repo not in repos_to_process:
                repos_to_process.append(base_repo)

        # First reset these repositories
        logger.info("Resetting specified repositories...")
        reset_repositories(repos_to_process, embedding_processor)

        # Then process them
        for repo_name in repos_to_process:
            process_repository_pair(
                repo_name, embedding_processor, github_manager)
    else:
        # Get all repositories from Sherlock's organization
        repos = get_sherlock_repositories()
        logger.info(f"Found {len(repos)} repositories")

        processed_base_repos = set()
        for repo in repos:
            # Skip judging repositories and already processed base repos
            if repo['name'].endswith('-judging'):
                continue
            base_repo = repo['name'].replace('-judging', '')
            if base_repo not in processed_base_repos:
                process_repository_pair(
                    base_repo, embedding_processor, github_manager)
                processed_base_repos.add(base_repo)

    # Print summary
    processed_repos = embedding_processor.get_processed_repositories()
    logger.info("\nProcessing Summary:")
    logger.info(f"Total repositories processed: {len(processed_repos)}")

    successful = [r for r in processed_repos if r['status'] == 'completed']
    failed = [r for r in processed_repos if r['status'] == 'error']

    logger.info(f"Successfully processed: {len(successful)}")
    logger.info(f"Failed to process: {len(failed)}")

    if failed:
        logger.info("\nFailed repositories:")
        for repo in failed:
            logger.info(
                f"- {repo['repo_name']}: {repo.get('error', 'Unknown error')}")


if __name__ == "__main__":
    main()
