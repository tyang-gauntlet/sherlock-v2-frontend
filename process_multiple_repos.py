#!/usr/bin/env python3
import os
import sys
from dotenv import load_dotenv
from services.github_repo_manager import GithubRepoManager
from services.embedding_processor import EmbeddingProcessor
import logging
from concurrent.futures import ProcessPoolExecutor, as_completed
import requests
from tqdm import tqdm
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def get_sherlock_repositories() -> list:
    """Get list of all repositories from Sherlock's GitHub organization"""
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
            f'https://api.github.com/orgs/sherlock-audit/repos?page={page}&per_page=100&type=all',
            headers=headers
        )
        if response.status_code != 200:
            raise Exception(f"Failed to fetch repositories: {response.text}")

        page_repos = response.json()
        if not page_repos:
            break

        # Only include repositories that exist and are accessible
        for repo in page_repos:
            # Check if repository exists and is accessible
            repo_url = repo['url']
            check_response = requests.get(repo_url, headers=headers)
            if check_response.status_code == 200:
                repos.append(repo)
            else:
                logger.warning(
                    f"Repository {repo['name']} is not accessible, skipping...")

        page += 1

    # Filter and pair repositories
    repo_pairs = {}
    for repo in repos:
        name = repo['name']
        if name.endswith('-judging'):
            base_name = name[:-8]  # Remove '-judging' suffix
            if base_name not in repo_pairs:
                repo_pairs[base_name] = {'judging': repo}
            elif 'base' in repo_pairs[base_name]:
                repo_pairs[base_name]['judging'] = repo
        else:
            if name not in repo_pairs:
                repo_pairs[name] = {'base': repo}
            elif 'judging' not in repo_pairs[name]:
                repo_pairs[name]['base'] = repo

    # Convert to list of complete pairs, prioritizing recent ones
    complete_pairs = []
    for base_name, pair in repo_pairs.items():
        if 'judging' in pair:  # Only process repos that have judging completed
            # Use SSH URLs for cloning
            if 'base' in pair:
                pair['base']['clone_url'] = pair['base']['ssh_url']
            pair['judging']['clone_url'] = pair['judging']['ssh_url']

            complete_pairs.append({
                'base_name': base_name,
                'base_repo': pair.get('base'),
                'judging_repo': pair['judging']
            })

    # Sort by creation date (most recent first)
    complete_pairs.sort(
        key=lambda x: x['judging_repo']['created_at'], reverse=True)

    # Log the repositories we're going to process
    logger.info("\nRepositories to process:")
    for pair in complete_pairs:
        logger.info(f"- {pair['base_name']}")
        if pair.get('base_repo'):
            logger.info(f"  Base: {pair['base_repo']['clone_url']}")
        logger.info(f"  Judging: {pair['judging_repo']['clone_url']}")

    return complete_pairs


def process_repo_pair(repo_pair: dict) -> tuple:
    """Process a single repository pair"""
    try:
        # Initialize services
        embedding_processor = EmbeddingProcessor(
            os.getenv('PINECONE_API_KEY'),
            "us-east-1-aws",
            'smartsmart'
        )
        github_manager = GithubRepoManager(os.getenv('GITHUB_TOKEN'))

        base_name = repo_pair['base_name']
        judging_repo = repo_pair['judging_repo']

        # Skip if already processed
        if embedding_processor.is_repository_processed(base_name):
            return base_name, "already processed"

        # Process the repository pair
        from scripts.process_sherlock_repos import process_repository_pair
        process_repository_pair(base_name, embedding_processor, github_manager)

        return base_name, "success"
    except Exception as e:
        return base_name, f"error: {str(e)}"


def main():
    """Main function to process all Sherlock repositories"""
    # Load environment variables
    load_dotenv()

    # Get all repository pairs
    logger.info("Fetching Sherlock repositories...")
    repo_pairs = get_sherlock_repositories()
    logger.info(
        f"Found {len(repo_pairs)} repository pairs with completed audits")

    # Process repositories in parallel
    # Limit to 4 workers to avoid API rate limits
    max_workers = min(os.cpu_count(), 4)
    results = []

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_repo_pair, pair)
                   for pair in repo_pairs]

        with tqdm(total=len(repo_pairs), desc="Processing repositories") as pbar:
            for future in as_completed(futures):
                repo_name, status = future.result()
                results.append((repo_name, status))
                pbar.update(1)

    # Print summary
    logger.info("\nProcessing Summary:")
    logger.info("==================")

    successful = [r for r in results if r[1] == "success"]
    skipped = [r for r in results if r[1] == "already processed"]
    failed = [r for r in results if r[1].startswith("error")]

    logger.info(f"Total repositories processed: {len(results)}")
    logger.info(f"Successfully processed: {len(successful)}")
    logger.info(f"Already processed (skipped): {len(skipped)}")
    logger.info(f"Failed to process: {len(failed)}")

    if failed:
        logger.info("\nFailed repositories:")
        for repo, error in failed:
            logger.info(f"- {repo}: {error}")


if __name__ == "__main__":
    main()
