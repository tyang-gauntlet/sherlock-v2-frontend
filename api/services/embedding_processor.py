import os
from typing import Dict, List
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer
import logging
from typing import Generator
import re
import openai  # Import openai module directly
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
import json
from dataclasses import asdict
from dotenv import load_dotenv
import datetime
import time
from functools import wraps

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


def retry_with_backoff(retries=3, backoff_in_seconds=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            x = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if x == retries:
                        raise
                    else:
                        x += 1
                        wait = (backoff_in_seconds * 2 ** x)
                        logger.warning(
                            f"Retrying {func.__name__} in {wait} seconds... (Attempt {x} of {retries})")
                        time.sleep(wait)
        return wrapper
    return decorator


@dataclass
class CodeReference:
    """Reference to a specific code location"""
    file_path: str
    start_line: int
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None
    context: Optional[str] = None


@dataclass
class VulnerabilityPattern:
    """Structured representation of a vulnerability pattern"""
    title: str
    severity: str
    description: str
    impact: str
    category: str
    code_references: List[CodeReference]
    mitigation: Optional[str] = None
    prerequisites: Optional[str] = None
    affected_components: Optional[List[str]] = None
    chain_specific: Optional[str] = None
    related_vulns: Optional[List[str]] = None


class EmbeddingProcessor:
    def __init__(self, pinecone_api_key: str, pinecone_environment: str, index_name: str):
        """
        Initialize the embedding processor with Pinecone connection and OpenAI
        """
        # Initialize OpenAI client
        openai_api_key = os.getenv('OPENAI_API_KEY')
        if not openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable is not set")

        # Set OpenAI API key (using v0.28.1 style)
        openai.api_key = openai_api_key
        self.openai = openai

        # Using a pre-trained sentence transformer model optimized for code
        self.model = SentenceTransformer(
            'flax-sentence-embeddings/st-codesearch-distilroberta-base')

        # Initialize Pinecone with new SDK
        self.pc = Pinecone(api_key=pinecone_api_key)
        self.index = self.pc.Index("smartsmart")
        self.processed_repos = self.index  # Use the same index for tracking

        # Initialize embedding cache
        self._embedding_cache = {}
        self._pending_embeddings = []
        self._max_pending = 200  # Maximum number of embeddings to hold before forced flush

    def _cache_key(self, text: str, prefix: str = "") -> str:
        """Generate a cache key for a text"""
        return f"{prefix}:{hash(text)}"

    def _get_cached_embedding(self, text: str, prefix: str = "") -> Optional[List[float]]:
        """Get embedding from cache if it exists"""
        return self._embedding_cache.get(self._cache_key(text, prefix))

    def _cache_embedding(self, text: str, embedding: List[float], prefix: str = ""):
        """Cache an embedding"""
        self._embedding_cache[self._cache_key(text, prefix)] = embedding

    def _batch_encode(self, texts: List[str]) -> List[List[float]]:
        """Encode multiple texts in a batch"""
        return self.model.encode(texts).tolist()

    @retry_with_backoff(retries=3)
    def delete_repository(self, repo_name: str) -> None:
        """Delete a repository and all its associated entries from Pinecone"""
        try:
            # Delete the repository tracking entry
            self.index.delete(ids=[repo_name])

            # Delete all entries with this repo_name in metadata
            # We'll do this by fetching and then deleting in batches
            query_vector = [0.0] * 767 + [1.0]
            results = self.index.query(
                vector=query_vector,
                top_k=10000,
                include_metadata=True,
                filter={"repo_name": repo_name}
            )

            # Collect all IDs to delete
            ids_to_delete = [match.id for match in results.matches]

            # Delete in batches of 100
            batch_size = 100
            for i in range(0, len(ids_to_delete), batch_size):
                batch = ids_to_delete[i:i + batch_size]
                self.index.delete(ids=batch)

            logger.debug(f"Deleted repository: {repo_name}")
        except Exception as e:
            logger.error(f"Error deleting repository {repo_name}: {str(e)}")
            raise

    @retry_with_backoff(retries=3)
    def track_processed_repository(self, repo_name: str, status: str = "completed", metadata: Optional[Dict] = None) -> None:
        """Track a processed repository in Pinecone with retry logic"""
        if not metadata:
            metadata = {}

        # Delete existing entries if any
        try:
            self.delete_repository(repo_name)
        except Exception as e:
            logger.debug(
                f"Error cleaning up old entries for {repo_name}: {str(e)}")

        # Create a vector with at least one non-zero value
        dummy_vector = [0.0] * 767 + [1.0]

        # Add both ISO format and timestamp for filtering
        now = datetime.datetime.utcnow()
        metadata.update({
            "status": status,
            "processed_at": now.isoformat(),
            "processed_at_ts": int(now.timestamp()),
            "repo_name": repo_name
        })

        # Ensure all metadata values are simple types
        for key, value in metadata.items():
            if isinstance(value, (dict, list)):
                metadata[key] = json.dumps(value)

        self.index.upsert(
            vectors=[{
                "id": repo_name,
                "values": dummy_vector,
                "metadata": metadata
            }]
        )
        logger.debug(f"Tracked repository: {repo_name}")

    @retry_with_backoff(retries=3)
    def get_processed_repositories(self) -> List[Dict]:
        """Get list of all processed repositories with retry logic"""
        # Query with a vector of correct dimension (768)
        dummy_vector = [0.0] * 767 + [1.0]

        # Get current timestamp for filtering
        current_time = datetime.datetime.utcnow()
        one_hour_ago = int(
            (current_time - datetime.timedelta(hours=1)).timestamp())

        results = self.index.query(
            vector=dummy_vector,
            top_k=10000,  # Large number to get all
            include_metadata=True,
            filter={
                # Only get entries from the last hour using timestamp
                "processed_at_ts": {"$gte": one_hour_ago}
            }
        )

        processed = []
        for match in results.matches:
            processed.append({
                "repo_name": match.metadata.get("repo_name"),
                "status": match.metadata.get("status"),
                "processed_at": match.metadata.get("processed_at"),
                **{k: v for k, v in match.metadata.items() if k not in ["repo_name", "status", "processed_at", "processed_at_ts"]}
            })

        return processed

    @retry_with_backoff(retries=3)
    def is_repository_processed(self, repo_name: str) -> bool:
        """Check if a repository has been processed with retry logic"""
        try:
            result = self.index.fetch(ids=[repo_name])
            return bool(result.vectors)
        except Exception:
            return False

    def process_solidity_file(self, file_data: Dict) -> List[Dict]:
        """
        Process a Solidity file and create embeddings for:
        1. Contract definitions
        2. Function definitions
        3. Important code blocks
        """
        content = file_data["content"]
        chunks = self._chunk_solidity_code(content)

        embeddings = []
        for chunk in chunks:
            # Add Solidity-specific context to improve embedding quality
            contextualized_text = self._add_code_context(
                chunk["text"], chunk["type"])
            embedding = self.model.encode(contextualized_text)

            # Create metadata for the chunk
            metadata = {
                "type": "solidity_code",
                "repo_name": file_data["repo_name"],
                "file_path": file_data["file_path"],
                "chunk_type": chunk["type"],
                "start_line": chunk["start_line"],
                "end_line": chunk["end_line"],
                "content": chunk["text"]
            }

            embeddings.append({
                "id": f"{file_data['repo_name']}_{file_data['file_path']}_{chunk['start_line']}",
                "values": embedding.tolist(),
                "metadata": metadata
            })

        return embeddings

    def _add_code_context(self, code: str, chunk_type: str) -> str:
        """Add context to code chunks to improve embedding quality"""
        if chunk_type == "contract":
            return f"Solidity smart contract definition: {code}"
        elif chunk_type == "function":
            return f"Solidity function implementation: {code}"
        elif chunk_type == "modifier":
            return f"Solidity modifier definition: {code}"
        elif chunk_type == "event":
            return f"Solidity event definition: {code}"
        return f"Solidity code: {code}"

    def _chunk_solidity_code(self, content: str) -> List[Dict]:
        """
        Chunk Solidity code into meaningful parts with improved security focus
        """
        chunks = []
        lines = content.split('\n')

        # Patterns for security-relevant code sections
        patterns = {
            'contract': r'^\s*contract\s+(\w+)',
            'function': r'^\s*function\s+(\w+)',
            'modifier': r'^\s*modifier\s+(\w+)',
            'event': r'^\s*event\s+(\w+)',
            'constructor': r'^\s*constructor\s*\(',
            'fallback': r'^\s*fallback\s*\(\)',
            'receive': r'^\s*receive\s*\(\)',
            'assembly': r'^\s*assembly\s*{'
        }

        current_chunk = []
        current_type = None
        start_line = 1
        in_block = False
        block_depth = 0

        for i, line in enumerate(lines, 1):
            # Track block depth
            block_depth += line.count('{') - line.count('}')
            in_block = block_depth > 0

            # Check for pattern matches
            matched = False
            for pattern_type, pattern in patterns.items():
                if re.match(pattern, line):
                    if current_chunk and not in_block:
                        chunks.append({
                            "text": "\n".join(current_chunk),
                            "type": current_type or "code_block",
                            "start_line": start_line,
                            "end_line": i - 1
                        })
                    current_chunk = [line]
                    current_type = pattern_type
                    start_line = i
                    matched = True
                    break

            if not matched:
                current_chunk.append(line)

            # Handle complete blocks
            if in_block and block_depth == 0:
                chunks.append({
                    "text": "\n".join(current_chunk),
                    "type": current_type or "code_block",
                    "start_line": start_line,
                    "end_line": i
                })
                current_chunk = []
                current_type = None
                start_line = i + 1

        # Add the last chunk
        if current_chunk:
            chunks.append({
                "text": "\n".join(current_chunk),
                "type": current_type or "code_block",
                "start_line": start_line,
                "end_line": len(lines)
            })

        # Add contract-wide chunk for full context
        if len(lines) > 0:
            chunks.append({
                "text": "\n".join(lines),
                "type": "full_contract",
                "start_line": 1,
                "end_line": len(lines)
            })

        return chunks

    def process_vulnerability_report(self, report_data: Dict, repo_path: Optional[str] = None) -> List[Dict]:
        """Process a vulnerability report using AI to extract structured information"""
        content = report_data["content"]
        vulnerability = self._extract_vulnerability_pattern(content, repo_path)
        embeddings = []

        # Generate a unique reference ID for this vulnerability
        vuln_ref_id = f"{report_data['repo_name']}_{report_data['report_file']}"

        # Store only essential metadata with code embeddings
        essential_metadata = {
            "type": "vulnerability_code",
            "repo_name": report_data["repo_name"],
            "report_file": report_data["report_file"],
            "severity": vulnerability.severity,
            "category": vulnerability.category,
            "ref_id": vuln_ref_id  # Reference to full metadata
        }

        # Store full vulnerability details in a single record
        full_metadata = {
            "type": "vulnerability_details",
            "repo_name": report_data["repo_name"],
            "report_file": report_data["report_file"],
            "title": vulnerability.title,
            "severity": vulnerability.severity,
            "category": vulnerability.category,
            "description": vulnerability.description,
            "impact": vulnerability.impact,
            "prerequisites": json.dumps(vulnerability.prerequisites) if vulnerability.prerequisites else "",
            "chain_specific": vulnerability.chain_specific or "",
            "affected_components": json.dumps(vulnerability.affected_components) if vulnerability.affected_components else "",
            "mitigation": vulnerability.mitigation or ""
        }

        # Create a dummy vector for the full metadata record (required by Pinecone)
        dummy_vector = [0.0] * 767 + [1.0]
        embeddings.append({
            "id": f"{vuln_ref_id}_details",
            "values": dummy_vector,
            "metadata": full_metadata
        })

        # Process code references - only store the actual code snippets
        for i, code_ref in enumerate(vulnerability.code_references):
            if code_ref.code_snippet:
                # Add code-specific context to improve embedding quality
                contextualized_code = f"""
                Vulnerability: {vulnerability.title}
                Category: {vulnerability.category}
                Code:
                {code_ref.code_snippet}
                """
                code_embedding = self.model.encode(contextualized_code)

                code_metadata = essential_metadata.copy()
                code_metadata.update({
                    "file_path": code_ref.file_path,
                    "start_line": str(code_ref.start_line),
                    "end_line": str(code_ref.end_line) if code_ref.end_line else str(code_ref.start_line),
                    "snippet_id": i  # To order multiple snippets
                })

            embeddings.append({
                "id": f"{vuln_ref_id}_code_{i}",
                "values": code_embedding.tolist(),
                "metadata": code_metadata
            })

        return embeddings

    def _extract_vulnerability_pattern(self, content: str, repo_path: Optional[str] = None) -> VulnerabilityPattern:
        """
        Use GPT to extract structured vulnerability information from the report
        """
        # First, extract any GitHub links and code references
        github_refs = self._extract_github_references(content)

        # Split content into chunks if it's too long
        content_chunks = self._split_content_into_chunks(content)
        all_data = []

        for chunk_idx, chunk in enumerate(content_chunks):
            prompt = f"""
            Analyze this {'part of the ' if len(content_chunks) > 1 else ''}smart contract vulnerability report and extract structured information.
            Pay special attention to any code references, file paths, or line numbers mentioned.
            
            Format the response as JSON with the following fields:
            - title: {'A clear title describing the vulnerability' if chunk_idx == 0 else 'Leave empty for continuation chunks'}
            - severity: {'The severity level' if chunk_idx == 0 else 'Leave empty for continuation chunks'}
            - description: {'Clear description of the vulnerability' if chunk_idx == 0 else 'Additional details for the vulnerability'}
            - impact: {'The potential impact' if chunk_idx == 0 else 'Additional impact details'}
            - category: {'The type of vulnerability (e.g., "access control", "input validation")' if chunk_idx == 0 else 'Leave empty for continuation chunks'}
            - code_references: Array of objects containing:
                - file_path: The path to the file (if mentioned)
                - start_line: Starting line number (if mentioned)
                - end_line: Ending line number (if mentioned)
                - code_snippet: The relevant code snippet (if shown)
                - context: Description of what this code reference shows
            - mitigation: How to fix the issue
            - prerequisites: Required conditions for the vulnerability
            - affected_components: List of affected components/functions
            - chain_specific: If the issue is specific to certain chains
            - related_vulns: Similar known vulnerabilities

            If you find any code snippets or references in the report, include them in the code_references array.
            For each code reference, provide as much context as possible about what that code shows.
            Ensure all line numbers are provided as integers, not strings.

            Report{' (Part ' + str(chunk_idx + 1) + '/' + str(len(content_chunks)) + ')' if len(content_chunks) > 1 else ''}:
            {chunk}

            Previously extracted GitHub references:
            {json.dumps(github_refs, indent=2)}
            """

            max_retries = 5
            base_delay = 2  # Start with 2 second delay

            for attempt in range(max_retries):
                try:
                    response = self.openai.ChatCompletion.create(
                        model="gpt-4",
                        messages=[
                            {"role": "system", "content": "You are a smart contract security expert. Analyze vulnerability reports and extract structured information, paying special attention to code references and their context."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.1,
                        request_timeout=15  # Reduced timeout to 15 seconds
                    )

                    result = response.choices[0].message['content']

                    try:
                        # Clean the response string - remove any markdown formatting
                        result = result.strip()
                        if result.startswith("```json"):
                            result = result[7:]
                        if result.endswith("```"):
                            result = result[:-3]
                        result = result.strip()

                        chunk_data = json.loads(result)

                        # Ensure lists are properly handled
                        if 'code_references' in chunk_data:
                            if isinstance(chunk_data['code_references'], str):
                                chunk_data['code_references'] = []
                            elif not isinstance(chunk_data['code_references'], list):
                                chunk_data['code_references'] = []

                        if 'affected_components' in chunk_data:
                            if isinstance(chunk_data['affected_components'], str):
                                chunk_data['affected_components'] = [
                                    chunk_data['affected_components']]
                            elif not isinstance(chunk_data['affected_components'], list):
                                chunk_data['affected_components'] = []

                        if 'related_vulns' in chunk_data:
                            if isinstance(chunk_data['related_vulns'], str):
                                chunk_data['related_vulns'] = [
                                    chunk_data['related_vulns']]
                            elif not isinstance(chunk_data['related_vulns'], list):
                                chunk_data['related_vulns'] = []

                        all_data.append(chunk_data)
                        break  # If we get here, we have valid JSON data
                    except json.JSONDecodeError as e:
                        if attempt == max_retries - 1:  # Last attempt
                            raise  # Re-raise on last attempt
                        continue  # Try again if we have more attempts

                except Exception as e:
                    error_msg = str(e)
                    if "timeout" in error_msg.lower() or "502" in error_msg:
                        if attempt < max_retries - 1:  # Not the last attempt
                            delay = base_delay * (2 ** attempt)
                            time.sleep(delay)
                            continue

                    # If we get here, it's either not a timeout/502 error or we're out of retries
                    if attempt == max_retries - 1:  # Last attempt
                        return VulnerabilityPattern(
                            title=content.split('\n')[0][:100],
                            severity="unknown",
                            description=content,
                            impact="unknown",
                            category="unknown",
                            code_references=[],
                            affected_components=[],
                            related_vulns=[]
                        )
                    continue  # Try again if we have more attempts

        # Merge all chunks data
        merged_data = self._merge_chunk_data(all_data)

        # Process code references
        code_refs = []
        for ref in merged_data.get("code_references", []):
            # Ensure line numbers are integers and handle None values
            try:
                start_line = int(ref.get("start_line", 1))
            except (TypeError, ValueError):
                start_line = 1

            try:
                end_line = int(ref.get("end_line", start_line))
            except (TypeError, ValueError):
                end_line = start_line

            # If we have a repo path, try to find the actual file
            code_snippet = ref.get("code_snippet")
            if repo_path and ref.get("file_path"):
                full_path = os.path.join(repo_path, ref["file_path"])
                if os.path.exists(full_path):
                    try:
                        with open(full_path, 'r') as f:
                            lines = f.readlines()
                            # Ensure line numbers are within bounds
                            start_idx = max(0, start_line - 1)
                            end_idx = min(len(lines), end_line)
                            code_snippet = "".join(lines[start_idx:end_idx])
                    except Exception as e:
                        logger.debug(
                            f"Error reading file {full_path}: {str(e)}")

            code_refs.append(CodeReference(
                file_path=ref.get("file_path", "unknown"),
                start_line=start_line,
                end_line=end_line,
                code_snippet=code_snippet,
                context=ref.get("context")
            ))

        return VulnerabilityPattern(
            title=merged_data.get("title", "Untitled"),
            severity=merged_data.get("severity", "unknown"),
            description=merged_data.get("description", ""),
            impact=merged_data.get("impact", ""),
            category=merged_data.get("category", "unknown"),
            code_references=code_refs,
            mitigation=merged_data.get("mitigation"),
            prerequisites=merged_data.get("prerequisites"),
            affected_components=merged_data.get("affected_components", []),
            chain_specific=merged_data.get("chain_specific"),
            related_vulns=merged_data.get("related_vulns", [])
        )

    def _extract_github_references(self, content: str) -> List[Dict]:
        """Extract GitHub references from markdown content"""
        refs = []

        # Pattern for GitHub links with line numbers
        github_patterns = [
            # Standard GitHub line reference
            r'https://github\.com/[^/]+/[^/]+/blob/[^/]+/(.+?)#L(\d+)(?:-L(\d+))?',
            # Source/File references in markdown
            r'\[(?:Source|File)\]\((?:https://github\.com/[^/]+/[^/]+/blob/[^/]+/(.+?)#L(\d+)(?:-L(\d+))?)\)',
            # Inline code references
            r'`([^`]+?\.sol)(?::(\d+)(?:-(\d+))?)?`'
        ]

        for pattern in github_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                file_path = match.group(1)
                start_line = int(match.group(2)) if match.group(2) else None
                end_line = int(match.group(3)) if match.group(
                    3) else start_line

                # Extract surrounding context
                context_lines = []
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if match.group(0) in line:
                        # Get 2 lines before and after for context
                        start = max(0, i - 2)
                        end = min(len(lines), i + 3)
                        context_lines = lines[start:end]
                        break

                refs.append({
                    "file_path": file_path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "context": "\n".join(context_lines) if context_lines else None
                })

        return refs

    @retry_with_backoff(retries=3)
    def store_embeddings(self, embeddings: List[Dict], batch_size: int = 100):
        """Store embeddings in Pinecone in batches with retry logic"""
        # Add to pending embeddings
        self._pending_embeddings.extend(embeddings)

        # If we've exceeded the maximum pending, or this is an explicit flush
        if len(self._pending_embeddings) >= self._max_pending or len(embeddings) >= batch_size:
            # Sort embeddings by type to optimize batching
            sorted_embeddings = sorted(
                self._pending_embeddings, key=lambda x: x['metadata'].get('type', ''))

            # Process in larger batches
            batch_size = min(200, len(sorted_embeddings)
                             )  # Use larger batch size
            for i in range(0, len(sorted_embeddings), batch_size):
                batch = sorted_embeddings[i:i + batch_size]
            self.index.upsert(vectors=batch)

            # Clear pending embeddings
            self._pending_embeddings = []

    def _chunk_markdown_content(self, content: str) -> List[Dict]:
        """
        Chunk markdown content into meaningful parts using regex patterns
        """
        # Split by headers
        chunks = []
        current_chunk = []
        current_type = None

        for line in content.split('\n'):
            if line.startswith('# '):
                if current_chunk:
                    chunks.append({
                        "text": "\n".join(current_chunk),
                        "type": current_type or "description"
                    })
                current_chunk = [line]
                current_type = self._determine_chunk_type(line.lower())
            else:
                current_chunk.append(line)

        # Add the last chunk
        if current_chunk:
            chunks.append({
                "text": "\n".join(current_chunk),
                "type": current_type or "description"
            })

        return chunks

    def _determine_chunk_type(self, header: str) -> str:
        """Determine the type of markdown chunk based on its header"""
        if any(word in header for word in ['impact', 'severity', 'risk']):
            return "impact"
        elif any(word in header for word in ['vulnerability', 'bug', 'issue']):
            return "description"
        elif any(word in header for word in ['code', 'poc', 'proof']):
            return "code_reference"
        return "description"

    def search_similar_vulnerabilities(self, code_chunk: Dict, top_k: int = 5) -> List[Dict]:
        """Search for similar vulnerabilities using code embeddings"""
        try:
            # Add more context to the code chunk based on its type
            context = self._add_vulnerability_context(code_chunk)

            # Create embedding for the code chunk
            code_embedding = self.model.encode(context)

            # Search for similar code patterns with lower threshold
            code_results = self.index.query(
                vector=code_embedding.tolist(),
                top_k=top_k * 2,  # Get more results initially
                include_metadata=True,
                filter={
                    "type": "vulnerability_code"
                }
            )

            vulnerabilities = []
            seen_refs = set()

            for match in code_results.matches:
                if match.score < 0.4:  # Lower similarity threshold for better recall
                    continue

                ref_id = match.metadata.get("ref_id")
                if ref_id in seen_refs:
                    continue
                seen_refs.add(ref_id)

                # Fetch full vulnerability details
                details_id = f"{ref_id}_details"
                details_result = self.index.fetch(ids=[details_id])

                if not details_result.vectors:
                    continue

                details = details_result.vectors[details_id].metadata

                vulnerability = {
                    "similarity_score": match.score,
                    "report_file": match.metadata.get("report_file"),
                    "repo_name": match.metadata.get("repo_name"),
                    "title": details.get("title"),
                    "severity": details.get("severity"),
                    "category": details.get("category"),
                    "description": details.get("description"),
                    "impact": details.get("impact"),
                    "prerequisites": details.get("prerequisites"),
                    "chain_specific": details.get("chain_specific"),
                    "mitigation": details.get("mitigation"),
                    "file_path": match.metadata.get("file_path"),
                    "start_line": match.metadata.get("start_line"),
                    "end_line": match.metadata.get("end_line")
                }
                vulnerabilities.append(vulnerability)

            return sorted(vulnerabilities, key=lambda x: x["similarity_score"], reverse=True)[:top_k]

        except Exception as e:
            logger.error(f"Error searching for vulnerabilities: {str(e)}")
            return []

    def _add_vulnerability_context(self, code_chunk: Dict) -> str:
        """Add security-focused context to code chunks"""
        chunk_type = code_chunk.get("type", "")
        text = code_chunk.get("text", "")

        # Add security-relevant keywords based on code patterns
        context_parts = []

        if "delegatecall" in text.lower():
            context_parts.append(
                "Potential delegatecall vulnerability context:")
        if "require" in text.lower() and ("owner" in text.lower() or "admin" in text.lower()):
            context_parts.append("Access control check context:")
        if "transfer" in text.lower() or "send" in text.lower() or "call" in text.lower():
            context_parts.append("External call context:")
        if "proposal" in text.lower() or "vote" in text.lower() or "governance" in text.lower():
            context_parts.append("Governance mechanism context:")
        if "timelock" in text.lower() or "delay" in text.lower():
            context_parts.append("Timelock mechanism context:")

        # Add type-specific context
        if chunk_type == "contract":
            context_parts.append("Contract vulnerability analysis:")
        elif chunk_type == "function":
            context_parts.append("Function vulnerability analysis:")
        elif chunk_type == "modifier":
            context_parts.append("Security modifier analysis:")

        # Combine context with code
        return "\n".join(context_parts + [text])

    def analyze_code_for_vulnerabilities(self, file_data: Dict) -> List[Dict]:
        """
        Analyze a Solidity file for potential vulnerabilities by comparing with known vulnerability patterns.

        Args:
            file_data: Dictionary containing the file content and metadata

        Returns:
            List of potential vulnerabilities found
        """
        try:
            # First chunk the code
            chunks = self._chunk_solidity_code(file_data["content"])

            all_vulnerabilities = []

            # For each code chunk, search for similar vulnerability patterns
            for chunk in chunks:
                # Skip empty or very small chunks
                if len(chunk["text"].strip()) < 50:
                    continue

                # Search for vulnerabilities
                vulnerabilities = self.search_similar_vulnerabilities(chunk)

                if vulnerabilities:
                    result = {
                        "code_location": {
                            "start_line": chunk["start_line"],
                            "end_line": chunk["end_line"],
                            "type": chunk["type"],
                            "code": chunk["text"]
                        },
                        "similar_vulnerabilities": vulnerabilities
                    }
                    all_vulnerabilities.append(result)

            return all_vulnerabilities

        except Exception as e:
            logger.error(f"Error analyzing code for vulnerabilities: {str(e)}")
            return []

    def _split_content_into_chunks(self, content: str, max_chunk_size: int = 4000) -> List[str]:
        """Split content into chunks that fit within OpenAI's context limit"""
        if len(content) <= max_chunk_size:
            return [content]

        chunks = []
        lines = content.split('\n')
        current_chunk = []
        current_size = 0

        for line in lines:
            line_size = len(line) + 1  # +1 for newline
            if current_size + line_size > max_chunk_size and current_chunk:
                chunks.append('\n'.join(current_chunk))
                current_chunk = []
                current_size = 0
            current_chunk.append(line)
            current_size += line_size

        if current_chunk:
            chunks.append('\n'.join(current_chunk))

        return chunks

    def _merge_chunk_data(self, chunks_data: List[Dict]) -> Dict:
        """Merge data from multiple chunks into a single vulnerability report"""
        if not chunks_data:
            return {}

        # Use the first chunk as base for metadata
        merged = chunks_data[0].copy()

        # Merge data from subsequent chunks
        for chunk in chunks_data[1:]:
            # Append descriptions
            if chunk.get('description'):
                if isinstance(merged.get('description', ''), list):
                    merged['description'] = ' '.join(merged['description'])
                if isinstance(chunk['description'], list):
                    chunk['description'] = ' '.join(chunk['description'])
                merged['description'] = (merged.get(
                    'description', '') + '\n' + chunk['description']).strip()

            # Append impact information
            if chunk.get('impact'):
                if isinstance(merged.get('impact', ''), list):
                    merged['impact'] = ' '.join(merged['impact'])
                if isinstance(chunk['impact'], list):
                    chunk['impact'] = ' '.join(chunk['impact'])
                merged['impact'] = (merged.get(
                    'impact', '') + '\n' + chunk['impact']).strip()

            # Extend code references
            if chunk.get('code_references'):
                if not isinstance(merged.get('code_references', []), list):
                    merged['code_references'] = []
                if not isinstance(chunk['code_references'], list):
                    chunk['code_references'] = [chunk['code_references']]
                merged['code_references'] = merged.get(
                    'code_references', []) + chunk['code_references']

            # Extend affected components
            if chunk.get('affected_components'):
                if not isinstance(merged.get('affected_components', []), list):
                    merged['affected_components'] = []
                if not isinstance(chunk['affected_components'], list):
                    chunk['affected_components'] = [
                        chunk['affected_components']]
                merged['affected_components'] = list(
                    set(merged.get('affected_components', []) + chunk['affected_components']))

            # Append mitigation information
            if chunk.get('mitigation'):
                if isinstance(merged.get('mitigation', ''), list):
                    merged['mitigation'] = ' '.join(merged['mitigation'])
                if isinstance(chunk['mitigation'], list):
                    chunk['mitigation'] = ' '.join(chunk['mitigation'])
                merged['mitigation'] = (merged.get(
                    'mitigation', '') + '\n' + chunk['mitigation']).strip()

            # Extend related vulnerabilities
            if chunk.get('related_vulns'):
                if not isinstance(merged.get('related_vulns', []), list):
                    merged['related_vulns'] = []
                if not isinstance(chunk['related_vulns'], list):
                    chunk['related_vulns'] = [chunk['related_vulns']]
                merged['related_vulns'] = list(
                    set(merged.get('related_vulns', []) + chunk['related_vulns']))

        return merged
