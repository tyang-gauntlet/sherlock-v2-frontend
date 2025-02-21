#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from services.github_repo_manager import GithubRepoManager
from services.embedding_processor import EmbeddingProcessor
import logging
from scripts.process_sherlock_repos import process_repository_pair

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def main():
    """Test processing a single repository pair"""
    # Load environment variables
    load_dotenv()

    # Initialize services
    embedding_processor = EmbeddingProcessor(
        os.getenv('PINECONE_API_KEY'),
        "us-east-1-aws",
        'smartsmart'
    )
    github_manager = GithubRepoManager(os.getenv('GITHUB_TOKEN'))

    # Process a recent repository with known vulnerabilities
    repo_name = "2024-11-tally"  # A recent repository with completed audit

    # First verify the database state
    logger.info("\nVerifying current database state:")
    logger.info("================================")

    # Check if repository was already processed
    if embedding_processor.is_repository_processed(repo_name):
        logger.info(f"Repository {repo_name} was already processed")
        # Get the stats
        processed_repos = embedding_processor.get_processed_repositories()
        for repo in processed_repos:
            if repo['repo_name'] == repo_name:
                logger.info("Processing details:")
                for key, value in repo.items():
                    logger.info(f"  {key}: {value}")

        # Delete existing entries to reprocess
        logger.info(f"\nDeleting existing entries for {repo_name}...")
        embedding_processor.delete_repository(repo_name)
        embedding_processor.delete_repository(f"{repo_name}-judging")

    # Process the repository
    logger.info(f"\nProcessing repository: {repo_name}")
    process_repository_pair(repo_name, embedding_processor, github_manager)

    # Verify the results
    logger.info("\nVerifying processing results:")
    logger.info("============================")
    processed_repos = embedding_processor.get_processed_repositories()
    for repo in processed_repos:
        if repo['repo_name'] == repo_name:
            logger.info("Processing details:")
            for key, value in repo.items():
                logger.info(f"  {key}: {value}")


if __name__ == "__main__":
    main()
