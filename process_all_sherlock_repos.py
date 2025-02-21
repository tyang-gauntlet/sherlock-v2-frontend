#!/usr/bin/env python3
import os
import sys
import tempfile
from dotenv import load_dotenv
from services.github_repo_manager import GithubRepoManager
from services.embedding_processor import EmbeddingProcessor
import logging
import requests
from tqdm import tqdm
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from typing import List, Dict, Tuple, Optional
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def get_total_repo_count(token: str) -> int:
    """Get total count of repositories using GraphQL"""
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }

    query = """
    {
        organization(login: "sherlock-audit") {
            repositories {
                totalCount
            }
        }
    }
    """

    response = requests.post(
        'https://api.github.com/graphql',
        headers=headers,
        json={'query': query}
    )

    if response.status_code == 200:
        data = response.json()
        return data['data']['organization']['repositories']['totalCount']
    else:
        logger.error(f"Failed to get repository count: {response.text}")
        return 0


def get_repositories_batch(token: str, page: int, per_page: int = 100) -> List[Dict]:
    """Get a batch of repositories using REST API"""
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    url = 'https://api.github.com/orgs/sherlock-audit/repos'
    params = {
        'page': page,
        'per_page': per_page,
        'type': 'all',  # Get all types including archived
        'sort': 'created',
        'direction': 'desc'
    }

    try:
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 403:
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            wait_time = max(reset_time - time.time(), 0)
            logger.warning(f"Rate limited. Waiting {wait_time:.0f} seconds...")
            time.sleep(wait_time + 1)
            return []

        if response.status_code != 200:
            logger.error(f"Failed to fetch repositories: {response.text}")
            return []

        repos = response.json()

        # Log the raw count before filtering
        logger.debug(f"Raw repositories in batch: {len(repos)}")
        return repos

    except Exception as e:
        logger.error(f"Error fetching repositories batch: {str(e)}")
        return []


def get_all_sherlock_repositories() -> List[Dict]:
    """Get all repositories from Sherlock's GitHub organization"""
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        raise ValueError("GITHUB_TOKEN environment variable is not set")

    # Get total count first
    total_count = get_total_repo_count(token)
    logger.info(f"Total repositories in organization: {total_count}")

    all_repos = []
    per_page = 100  # Increased page size
    total_pages = (total_count + per_page - 1) // per_page

    for page in range(1, total_pages + 1):
        logger.info(f"Fetching page {page}/{total_pages}...")

        repos = get_repositories_batch(token, page, per_page)
        if not repos:
            logger.warning(
                f"No repositories returned for page {page}, retrying...")
            time.sleep(2)
            repos = get_repositories_batch(token, page, per_page)
            if not repos:
                logger.error(f"Failed to fetch page {page} after retry")
                continue

        # Log raw repos before filtering
        logger.info(f"Retrieved {len(repos)} repositories from page {page}")

        # Only filter out forks, keep archived repos
        fork_count = sum(1 for repo in repos if repo['fork'])
        archived_count = sum(1 for repo in repos if repo['archived'])

        # Filter out only forks
        valid_repos = [
            repo for repo in repos
            if not repo['fork']  # Only exclude forks
        ]

        all_repos.extend(valid_repos)
        logger.info(f"Page {page} stats:")
        logger.info(f"  Total repos: {len(repos)}")
        logger.info(f"  Archived (included): {archived_count}")
        logger.info(f"  Forks (excluded): {fork_count}")
        logger.info(f"  Valid repos this page: {len(valid_repos)}")

        # Add small delay between batches
        time.sleep(0.5)

    logger.info(f"\nFinal Statistics:")
    logger.info(f"Total repositories found: {total_count}")
    logger.info(f"Total valid repositories fetched: {len(all_repos)}")

    # Log some repository details for verification
    logger.info("\nRepository names (first 10):")
    for repo in all_repos[:10]:
        logger.info(
            f"- {repo['name']} (Created: {repo['created_at']}, {'Archived' if repo.get('archived') else 'Active'})")
    if len(all_repos) > 10:
        logger.info(f"... and {len(all_repos) - 10} more")

    return all_repos


def pair_repositories(repos: List[Dict]) -> List[Dict]:
    """Pair main repositories with their judging counterparts"""
    pairs = {}

    for repo in repos:
        name = repo['name']
        if name.endswith('-judging'):
            base_name = name[:-8]
            if base_name not in pairs:
                pairs[base_name] = {'judging': repo}
        else:
            if name not in pairs:
                pairs[name] = {'main': repo}
            else:
                pairs[name]['main'] = repo

    # Convert to list of complete pairs
    complete_pairs = []
    for base_name, pair in pairs.items():
        if 'judging' in pair:  # Only include pairs with judging repos
            complete_pairs.append({
                'base_name': base_name,
                'main_repo': pair.get('main'),
                'judging_repo': pair['judging']
            })

    # Sort by creation date (most recent first)
    complete_pairs.sort(
        key=lambda x: x['judging_repo']['created_at'],
        reverse=True
    )

    return complete_pairs


def extract_vulnerability_patterns(content: str) -> List[Dict]:
    """Extract vulnerability patterns from markdown content"""
    patterns = []

    # Split content into sections (handle both ## and # headers)
    sections = re.split(r'(?m)^#{1,2}\s+', content)

    for section in sections:
        # Skip empty sections
        if not section.strip():
            continue

        # Try to extract vulnerability information
        title_match = re.search(r'^([^\n]+)', section)
        severity_match = re.search(
            r'(?:severity|impact|risk):\s*(critical|high|medium|low)', section.lower())
        category_match = re.search(
            r'(?:type|category|class):\s*([^\n]+)', section, re.IGNORECASE)

        # Extract code blocks with their language
        code_blocks = []
        for match in re.finditer(r'```(\w*)\n(.*?)```', section, re.DOTALL):
            lang = match.group(1) or 'unknown'
            code = match.group(2).strip()
            if code:  # Only add non-empty code blocks
                code_blocks.append({
                    'language': lang,
                    'code': code
                })

        # Extract file references
        file_refs = []
        file_patterns = [
            r'(?:file|in):\s*`?([^`\n]+\.sol)`?(?:[^\n]*?(?:line|L):?\s*(\d+)(?:\s*-\s*L?(\d+))?)?',
            r'https://github\.com/[^/]+/[^/]+/blob/[^/]+/(.+?)(?:#L(\d+)(?:-L(\d+))?)?'
        ]

        for pattern in file_patterns:
            for match in re.finditer(pattern, section, re.IGNORECASE):
                file_path = match.group(1)
                start_line = int(match.group(2)) if match.group(2) else None
                end_line = int(match.group(3)) if match.group(
                    3) else start_line
                if file_path.endswith('.sol'):  # Only include Solidity files
                    file_refs.append({
                        'file': file_path,
                        'start_line': start_line,
                        'end_line': end_line
                    })

        # Extract impact and description
        impact_match = re.search(
            r'(?s)impact:?\s*([^\n]+(?:\n(?!\n).*)*)', section, re.IGNORECASE)
        description_match = re.search(
            r'(?s)description:?\s*([^\n]+(?:\n(?!\n).*)*)', section, re.IGNORECASE)

        # Extract proof of concept if available
        poc_match = re.search(
            r'(?s)(?:proof\s*of\s*concept|poc):?\s*([^\n]+(?:\n(?!\n).*)*)', section, re.IGNORECASE)

        # Extract mitigation steps
        mitigation_match = re.search(
            r'(?s)(?:mitigation|recommendation|fix):?\s*([^\n]+(?:\n(?!\n).*)*)', section, re.IGNORECASE)

        if title_match:
            pattern = {
                'title': title_match.group(1).strip(),
                'severity': severity_match.group(1) if severity_match else 'unknown',
                'category': category_match.group(1).strip() if category_match else 'unknown',
                'description': description_match.group(1).strip() if description_match else section[:500].strip(),
                'impact': impact_match.group(1).strip() if impact_match else None,
                'code_samples': code_blocks,
                'file_references': file_refs,
                'proof_of_concept': poc_match.group(1).strip() if poc_match else None,
                'mitigation': mitigation_match.group(1).strip() if mitigation_match else None
            }

            # Clean up the pattern
            pattern = {k: v for k, v in pattern.items() if v is not None}
            patterns.append(pattern)

    return patterns


def process_repository_pair(repo_pair: Dict, embedding_processor: EmbeddingProcessor, github_manager: GithubRepoManager) -> Tuple[str, List[Dict]]:
    """Process a single repository pair with proper cleanup"""
    base_name = repo_pair['base_name']
    judging_repo = repo_pair['judging_repo']

    try:
        # Create temporary directory for this repository
        with tempfile.TemporaryDirectory() as temp_dir:
            judging_dir = os.path.join(temp_dir, 'judging')

            # Clone judging repository
            if not github_manager.clone_repository(judging_repo, judging_dir):
                return base_name, []

            # Process vulnerability reports
            patterns = []
            for item in github_manager.process_repository_content(judging_repo, judging_dir):
                if item["type"] == "vulnerability_report":
                    report_path = os.path.join(
                        judging_dir, item["report_file"])
                    try:
                        with open(report_path, 'r') as f:
                            content = f.read()
                            extracted = extract_vulnerability_patterns(content)
                            patterns.extend(extracted)
                    except Exception as e:
                        logger.error(
                            f"Error processing report {report_path}: {str(e)}")
                        continue

            # Process and store embeddings for each pattern
            logger.info(
                f"Processing embeddings for {len(patterns)} vulnerability patterns")
            for pattern in patterns:
                try:
                    # Create report data structure
                    report_data = {
                        "content": pattern.get('description', ''),
                        "repo_name": base_name,
                        "report_file": item.get("report_file", "unknown"),
                    }

                    # Process the vulnerability report and create embeddings
                    embeddings = embedding_processor.process_vulnerability_report(
                        report_data)

                    # Store the embeddings in batches
                    if embeddings:
                        logger.info(
                            f"Storing {len(embeddings)} embeddings for pattern")
                        embedding_processor.store_embeddings(embeddings)
                except Exception as e:
                    logger.error(
                        f"Error processing embeddings for pattern: {str(e)}")
                    continue

            # Track this repository as processed
            embedding_processor.track_processed_repository(
                base_name,
                status="completed",
                metadata={
                    "patterns_count": len(patterns),
                    "processed_at": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            )

            return base_name, patterns

    except Exception as e:
        logger.error(f"Error processing {base_name}: {str(e)}")
        return base_name, []


def save_patterns(patterns: Dict[str, List[Dict]], output_file: str):
    """Save extracted patterns to a JSON file"""
    with open(output_file, 'w') as f:
        json.dump(patterns, f, indent=2)


def analyze_patterns(patterns: Dict[str, List[Dict]]) -> Dict:
    """Analyze the extracted vulnerability patterns and provide a summary"""
    summary = {
        "total_patterns": 0,
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
        "categories": {},
        "repos_with_patterns": set(),
        "patterns_with_code": 0,
        "patterns_with_poc": 0,
        "patterns_with_mitigation": 0
    }

    for repo_name, repo_patterns in patterns.items():
        if repo_patterns:
            summary["repos_with_patterns"].add(repo_name)
            for pattern in repo_patterns:
                summary["total_patterns"] += 1

                # Count severities
                severity = pattern.get("severity", "unknown").lower()
                if severity in summary["severity_counts"]:
                    summary["severity_counts"][severity] += 1
                else:
                    summary["severity_counts"]["unknown"] += 1

                # Count categories
                category = pattern.get("category", "unknown")
                if category != "unknown":
                    summary["categories"][category] = summary["categories"].get(
                        category, 0) + 1

                # Count patterns with code samples
                if pattern.get("code_samples"):
                    summary["patterns_with_code"] += 1

                # Count patterns with proof of concept
                if pattern.get("proof_of_concept"):
                    summary["patterns_with_poc"] += 1

                # Count patterns with mitigation
                if pattern.get("mitigation"):
                    summary["patterns_with_mitigation"] += 1

    # Convert repos_with_patterns to length for JSON serialization
    summary["repos_with_patterns"] = len(summary["repos_with_patterns"])
    return summary


def process_repositories_in_batches(repo_pairs: List[Dict], embedding_processor: EmbeddingProcessor, github_manager: GithubRepoManager, batch_size: int = 5) -> Dict[str, List[Dict]]:
    """Process repository pairs one at a time with immediate cleanup"""
    patterns = {}
    total_pairs = len(repo_pairs)

    for idx, repo_pair in enumerate(repo_pairs, 1):
        base_name = repo_pair['base_name']
        logger.info(
            f"\nProcessing repository {idx}/{total_pairs}: {base_name}")

        try:
            # Create a temporary directory for this repository
            with tempfile.TemporaryDirectory() as temp_dir:
                logger.info(f"Created temporary directory: {temp_dir}")

                # Process single repository
                repo_patterns = process_repository_pair(
                    repo_pair, embedding_processor, github_manager)[1]
                patterns[base_name] = repo_patterns

                logger.info(f"Completed processing {base_name}")

            # Directory is automatically cleaned up when we exit the with block
            logger.info(f"Cleaned up temporary directory for {base_name}")

        except Exception as e:
            logger.error(f"Error processing {base_name}: {str(e)}")
            patterns[base_name] = []
            continue

        # Add delay between repositories
        if idx < total_pairs:
            logger.info("Waiting before next repository...")
            time.sleep(2)

        # Save progress every 5 repositories
        if idx % 5 == 0:
            progress_file = "vulnerability_patterns_progress.json"
            logger.info(f"Saving progress to {progress_file}")
            save_patterns(patterns, progress_file)

    return patterns


def main():
    """Main function to process all repositories"""
    # Load environment variables
    load_dotenv()

    # Initialize services
    github_token = os.getenv('GITHUB_TOKEN')
    pinecone_api_key = os.getenv('PINECONE_API_KEY')

    if not github_token:
        raise ValueError("GITHUB_TOKEN environment variable is not set")
    if not pinecone_api_key:
        raise ValueError("PINECONE_API_KEY environment variable is not set")

    github_manager = GithubRepoManager(github_token)
    embedding_processor = EmbeddingProcessor(
        pinecone_api_key=pinecone_api_key,
        pinecone_environment="us-east-1-aws",
        index_name="smartsmart"
    )

    # Get all repositories
    repos = get_all_sherlock_repositories()
    logger.info(f"Found {len(repos)} repositories")

    # Pair repositories
    repo_pairs = pair_repositories(repos)
    logger.info(f"Found {len(repo_pairs)} repository pairs")

    # Process repository pairs in batches
    patterns = process_repositories_in_batches(
        repo_pairs,
        embedding_processor,
        github_manager,
        batch_size=5
    )

    # Save patterns to file
    output_file = "vulnerability_patterns.json"
    save_patterns(patterns, output_file)
    logger.info(f"\nExtracted patterns saved to {output_file}")

    # Analyze patterns
    summary = analyze_patterns(patterns)
    logger.info("\nProcessing Summary:")
    logger.info(f"Total repositories processed: {len(repo_pairs)}")
    logger.info(
        f"Repositories with patterns: {summary['repos_with_patterns']}")
    logger.info(
        f"Total vulnerability patterns extracted: {summary['total_patterns']}")
    logger.info("\nSeverity Distribution:")
    for severity, count in summary['severity_counts'].items():
        logger.info(f"  {severity.capitalize()}: {count}")
    logger.info("\nPattern Quality Metrics:")
    logger.info(
        f"  Patterns with code samples: {summary['patterns_with_code']}")
    logger.info(
        f"  Patterns with proof of concept: {summary['patterns_with_poc']}")
    logger.info(
        f"  Patterns with mitigation steps: {summary['patterns_with_mitigation']}")
    if summary['categories']:
        logger.info("\nVulnerability Categories:")
        for category, count in summary['categories'].items():
            logger.info(f"  {category}: {count}")


if __name__ == "__main__":
    main()
