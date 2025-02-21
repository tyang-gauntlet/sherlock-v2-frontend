#!/usr/bin/env python3.11

import os
import argparse
from services.github_repo_manager import GithubRepoManager
from services.embedding_processor import EmbeddingProcessor
import logging
from dotenv import load_dotenv
import shutil
from collections import defaultdict
import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
import json
import tempfile

# Configure logging with a more visible format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

# Create logger
logger = logging.getLogger(__name__)

# Add a stream handler if there isn't one
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

# Ensure logger is not filtered
logger.setLevel(logging.INFO)
logger.propagate = True


@dataclass
class VulnerabilityData:
    """Structured representation of vulnerability data from audit logs"""
    title: str
    severity: str
    report_file: str
    repo_name: str
    # List of {file_path, start_line, end_line, code, context}
    code_snippets: List[Dict[str, any]]
    description: Optional[str] = None
    impact: Optional[str] = None
    category: Optional[str] = None


def extract_code_references(content: str) -> List[Dict]:
    """Extract code references and snippets from markdown content"""
    refs = []

    # Patterns for code references
    patterns = [
        # GitHub line references
        r'https://github\.com/[^/]+/[^/]+/blob/[^/]+/(.+?)#L(\d+)(?:-L(\d+))?',
        # Markdown code blocks with file references
        r'```solidity\s*(?:\/\/|#)\s*([^:\n]+):(\d+)(?:-(\d+))?\n(.*?)```',
        # Inline code references
        r'`([^`]+?\.sol)(?::(\d+)(?:-(\d+))?)?`'
    ]

    for pattern in patterns:
        matches = re.finditer(pattern, content, re.DOTALL)
        for match in matches:
            file_path = match.group(1)
            start_line = int(match.group(2)) if match.group(2) else None
            end_line = int(match.group(3)) if match.group(
                3) and match.group(3).isdigit() else start_line

            # Extract code snippet if available (from markdown code blocks)
            code_snippet = match.group(4).strip() if len(
                match.groups()) > 3 else None

            # Get surrounding context
            context_lines = []
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if match.group(0) in line:
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    context_lines = lines[start:end]
                    break

            if file_path and start_line:
                refs.append({
                    "file_path": file_path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "code": code_snippet,
                    "context": "\n".join(context_lines) if context_lines else None
                })

    return refs


def normalize_audit_report(content: str, report_file: str, repo_name: str) -> Optional[VulnerabilityData]:
    """Extract structured data from an audit report without using AI"""
    try:
        lines = content.split('\n')
        title = ""
        severity = "unknown"
        description = []
        impact = []
        category = "unknown"

        # Extract basic metadata
        for line in lines:
            line = line.strip()
            if not title and line.startswith('# '):
                title = line.replace('# ', '').strip()
            elif 'severity' in line.lower():
                # Try to extract severity level
                sev_match = re.search(
                    r'severity:?\s*(critical|high|medium|low)', line.lower())
                if sev_match:
                    severity = sev_match.group(1).capitalize()
            elif 'impact' in line.lower():
                impact.append(line)
            elif any(cat in line.lower() for cat in ['vulnerability type', 'category', 'issue type']):
                category = line.split(':')[-1].strip()

        # Extract code references
        code_refs = extract_code_references(content)

        # Create vulnerability data object
        vuln_data = VulnerabilityData(
            title=title or report_file,  # Use filename if no title found
            severity=severity,
            report_file=report_file,
            repo_name=repo_name,
            code_snippets=code_refs,
            description="\n".join(description) if description else None,
            impact="\n".join(impact) if impact else None,
            category=category
        )

        return vuln_data
    except Exception as e:
        logger.error(f"Error normalizing report {report_file}: {str(e)}")
        return None


def process_vulnerability_reports(reports_dir: str, repo_name: str, embedding_processor: EmbeddingProcessor) -> List[VulnerabilityData]:
    """Process all vulnerability reports in a directory"""
    vulnerabilities = []

    for root, _, files in os.walk(reports_dir):
        for file in files:
            if file.endswith('.md'):
                try:
                    with open(os.path.join(root, file), 'r') as f:
                        content = f.read()
                        vuln_data = normalize_audit_report(
                            content, file, repo_name)
                        if vuln_data and vuln_data.code_snippets:  # Only include if we found code references
                            vulnerabilities.append(vuln_data)
                except Exception as e:
                    logger.error(f"Error reading file {file}: {str(e)}")

    return vulnerabilities


def create_embeddings_for_vulnerabilities(vulnerabilities: List[VulnerabilityData], embedding_processor: EmbeddingProcessor):
    """Create embeddings for vulnerability code snippets"""
    for vuln in vulnerabilities:
        for i, snippet in enumerate(vuln.code_snippets):
            if not snippet.get('code'):
                continue

            # Create context-enhanced code representation
            contextualized_code = f"""
            Title: {vuln.title}
            Severity: {vuln.severity}
            Category: {vuln.category}
            File: {snippet['file_path']}
            Code:
            {snippet['code']}
            """

            # Generate embedding
            embedding = embedding_processor.model.encode(contextualized_code)

            # Create metadata
            metadata = {
                "type": "vulnerability_code",
                "repo_name": vuln.repo_name,
                "report_file": vuln.report_file,
                "title": vuln.title,
                "severity": vuln.severity,
                "category": vuln.category,
                "file_path": snippet['file_path'],
                "start_line": snippet['start_line'],
                "end_line": snippet['end_line'],
                "context": snippet['context']
            }

            # Create vector record
            vector = {
                "id": f"{vuln.repo_name}_{vuln.report_file}_{i}",
                "values": embedding.tolist(),
                "metadata": metadata
            }

            # Store embedding
            embedding_processor.store_embeddings([vector])


def process_repository_pair(repo_name: str, embedding_processor: EmbeddingProcessor, github_manager: GithubRepoManager) -> None:
    """Process a repository pair focusing on vulnerability data extraction"""
    base_url = "https://github.com/sherlock-audit"
    temp_dir = tempfile.mkdtemp()

    try:
        # Only process judging repository
        judging_repo_name = f"{repo_name}-judging"
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
            # Process vulnerability reports
            vulnerabilities = process_vulnerability_reports(
                judging_repo_dir, judging_repo_name, embedding_processor)
            logger.info(
                f"Found {len(vulnerabilities)} vulnerability reports with code references")

            # Create embeddings
            create_embeddings_for_vulnerabilities(
                vulnerabilities, embedding_processor)
            logger.info(f"Created embeddings for vulnerability code snippets")

            # Track successful processing
            embedding_processor.track_processed_repository(repo_name, "completed", {
                "judging_repo_url": judging_repo_url,
                "vulnerability_count": len(vulnerabilities)
            })
    except Exception as e:
        logger.error(f"Error processing repository {repo_name}: {str(e)}")
        embedding_processor.track_processed_repository(repo_name, "error", {
            "error": str(e)
        })
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


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
    parser.add_argument('repo_names', nargs='*',
                        help='Optional: Specific repository names to process')
    args = parser.parse_args()

    # Load environment variables
    load_dotenv()
    logger.info("Starting repository processing...")

    # Use args or environment variables
    github_token = args.github_token or os.getenv('GITHUB_TOKEN')
    pinecone_api_key = args.pinecone_api_key or os.getenv('PINECONE_API_KEY')
    pinecone_environment = args.pinecone_environment or os.getenv(
        'PINECONE_ENVIRONMENT')

    if not all([github_token, pinecone_api_key, pinecone_environment]):
        logger.error(
            "Missing required credentials. Please provide them via arguments or environment variables.")
        return

    logger.info("Initializing services...")
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
        logger.info(f"Created temporary directory: {temp_dir}")

        if args.repo_names:
            logger.info(f"Processing specific repositories: {args.repo_names}")
            for repo_name in args.repo_names:
                logger.info(f"Processing repository: {repo_name}")
                process_repository_pair(
                    repo_name, embedding_processor, repo_manager)
        else:
            # Fetch all repositories
            logger.info(
                "Fetching repository list from Sherlock Audit organization...")
            repos = repo_manager.get_all_repositories()
            logger.info(f"Found {len(repos)} repositories")

            # Group related repositories
            repo_groups = group_related_repos(repos)
            logger.info(
                f"Found {len(repo_groups)} repository groups to process")

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
                logger.info(
                    f"Completed processing repository group: {base_name}")

        logger.info("All repository groups processed")

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        raise
    finally:
        # Clean up temporary directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logger.info("Cleaned up temporary directory")


if __name__ == "__main__":
    main()
