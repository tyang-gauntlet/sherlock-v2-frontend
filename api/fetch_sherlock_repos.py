import os
import argparse
from services.github_repo_manager import GithubRepoManager
from services.embedding_processor import EmbeddingProcessor
import logging
from dotenv import load_dotenv
import shutil
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def group_related_repos(repos):
    """Group repositories by their base name (removing -judging suffix)"""
    repo_groups = defaultdict(dict)

    for repo in repos:
        base_name = repo["name"].replace("-judging", "")
        if repo["is_judging"]:
            repo_groups[base_name]["audit"] = repo
        else:
            repo_groups[base_name]["codebase"] = repo

    return repo_groups


def process_repo_pair(repo_manager, embedding_processor, codebase_repo, audit_repo, temp_dir):
    """Process a pair of related repositories (codebase and its audit)"""
    codebase_path = audit_path = None

    try:
        if codebase_repo:
            codebase_path = os.path.join(temp_dir, "codebase")
            logger.info(
                f"Cloning codebase repository: {codebase_repo['name']}")
            repo_manager.clone_repository(codebase_repo, codebase_path)

        if audit_repo:
            audit_path = os.path.join(temp_dir, "audit")
            logger.info(f"Cloning audit repository: {audit_repo['name']}")
            repo_manager.clone_repository(audit_repo, audit_path)

        # Process codebase first if it exists
        if codebase_path:
            logger.info(
                f"Processing Solidity files from: {codebase_repo['name']}")
            for item in repo_manager.process_repository_content(codebase_repo, codebase_path):
                if item["type"] == "solidity_file":
                    embeddings = embedding_processor.process_solidity_file(
                        item)
                    if embeddings:
                        embedding_processor.store_embeddings(embeddings)
                        logger.info(
                            f"Stored {len(embeddings)} embeddings for {item['file_path']}")

        # Then process audit reports if they exist
        if audit_path:
            logger.info(
                f"Processing vulnerability reports from: {audit_repo['name']}")
            for item in repo_manager.process_repository_content(audit_repo, audit_path):
                if item["type"] == "vulnerability_report":
                    embeddings = embedding_processor.process_vulnerability_report(
                        item)
                    if embeddings:
                        embedding_processor.store_embeddings(embeddings)
                        logger.info(
                            f"Stored {len(embeddings)} embeddings for {item['report_file']}")

    except Exception as e:
        logger.error(f"Error processing repositories: {str(e)}")
    finally:
        # Clean up repository directories
        if codebase_path and os.path.exists(codebase_path):
            shutil.rmtree(codebase_path)
        if audit_path and os.path.exists(audit_path):
            shutil.rmtree(audit_path)


def main():
    parser = argparse.ArgumentParser(
        description='Process Sherlock Audit repositories and create embeddings')
    parser.add_argument('--github-token', help='GitHub personal access token')
    parser.add_argument('--pinecone-api-key', help='Pinecone API key')
    parser.add_argument('--pinecone-environment', help='Pinecone environment')
    parser.add_argument(
        '--pinecone-index', default='sherlock-audit-code', help='Pinecone index name')
    args = parser.parse_args()

    # Load environment variables
    load_dotenv()

    # Use args or environment variables
    github_token = args.github_token or os.getenv('GITHUB_TOKEN')
    pinecone_api_key = args.pinecone_api_key or os.getenv('PINECONE_API_KEY')
    pinecone_environment = args.pinecone_environment or os.getenv(
        'PINECONE_ENVIRONMENT')

    if not all([github_token, pinecone_api_key, pinecone_environment]):
        logger.error(
            "Missing required credentials. Please provide them via arguments or environment variables.")
        return

    # Initialize services
    repo_manager = GithubRepoManager(github_token)
    embedding_processor = EmbeddingProcessor(
        pinecone_api_key,
        pinecone_environment,
        args.pinecone_index
    )

    try:
        # Create temporary directory for processing
        temp_dir = os.path.join(os.getcwd(), "temp_repos")
        os.makedirs(temp_dir, exist_ok=True)

        # Fetch all repositories
        logger.info(
            "Fetching repository list from Sherlock Audit organization...")
        repos = repo_manager.get_all_repositories()

        # Group related repositories
        repo_groups = group_related_repos(repos)
        logger.info(f"Found {len(repo_groups)} repository groups to process")

        # Process each group
        for base_name, group in repo_groups.items():
            logger.info(f"Processing repository group: {base_name}")
            process_repo_pair(
                repo_manager,
                embedding_processor,
                group.get("codebase"),
                group.get("audit"),
                temp_dir
            )
            logger.info(f"Completed processing repository group: {base_name}")

        logger.info("All repository groups processed")

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        raise
    finally:
        # Clean up temporary directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    main()
