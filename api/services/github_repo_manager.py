import os
import json
import tempfile
import shutil
from typing import Dict, List, Optional, Generator, Tuple
from github import Github
from git import Repo
import logging
from datetime import datetime
import glob
import re
import git

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SolidityProcessor:
    @staticmethod
    def normalize_solidity_code(code: str) -> str:
        """Normalize Solidity code by removing comments and standardizing whitespace"""
        # Remove single-line comments
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        # Remove multi-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        # Normalize whitespace
        code = re.sub(r'\s+', ' ', code)
        return code.strip()

    @staticmethod
    def extract_code_context(file_path: str, start_line: int, end_line: int) -> str:
        """Extract code context with surrounding lines"""
        with open(file_path, 'r') as f:
            lines = f.readlines()

        # Add context lines before and after
        context_range = 5
        start = max(0, start_line - context_range)
        end = min(len(lines), end_line + context_range)

        return ''.join(lines[start:end])


class GithubRepoManager:
    def __init__(self, github_token: str):
        self.github_token = github_token

    def clone_repository(self, repo_info: Dict, target_dir: str) -> bool:
        """Clone a repository to the target directory"""
        try:
            logger.info(
                f"Preparing to clone {repo_info['name']} to {target_dir}")

            # Clean up target directory if it exists
            if os.path.exists(target_dir):
                logger.info(f"Cleaning up existing directory: {target_dir}")
                shutil.rmtree(target_dir)

            # Create target directory
            os.makedirs(target_dir, exist_ok=True)

            # Get clone URL
            clone_url = repo_info.get('clone_url')
            if not clone_url:
                logger.error(f"No clone URL provided for {repo_info['name']}")
                return False

            logger.info(f"Cloning repository: {repo_info['name']}")

            # Handle SSH URLs
            if clone_url.startswith('git@'):
                # Use SSH key authentication
                Repo.clone_from(clone_url, target_dir)
            else:
                # Use HTTPS with token authentication
                auth_url = clone_url.replace(
                    'https://',
                    f'https://{self.github_token}@'
                )
                Repo.clone_from(auth_url, target_dir)

            logger.info(f"Successfully cloned {repo_info['name']}")
            return True

        except Exception as e:
            logger.error(
                f"Error cloning repository {repo_info['name']}: {str(e)}")
            return False

    def process_repository_content(self, repo_info: Dict, repo_path: str) -> Generator[Dict, None, None]:
        """Process repository content based on type"""
        try:
            # Check if repository name ends with '-judging'
            if repo_info['name'].endswith('-judging'):
                yield from self._process_judging_repository(repo_path)
            else:
                yield from self._process_main_repository(repo_path)
        except Exception as e:
            logger.error(f"Error processing repository content: {str(e)}")

    def _process_judging_repository(self, repo_path: str) -> Generator[Dict, None, None]:
        """Process judging repository content"""
        # Look for markdown files in the root directory first
        for file in os.listdir(repo_path):
            if file.endswith('.md'):
                yield {
                    "type": "vulnerability_report",
                    "report_file": file
                }

        # Then look in the 'report' or 'reports' directory if it exists
        report_dirs = ['report', 'reports', 'findings', 'issues']
        for report_dir in report_dirs:
            dir_path = os.path.join(repo_path, report_dir)
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                for root, _, files in os.walk(dir_path):
                    for file in files:
                        if file.endswith('.md'):
                            rel_path = os.path.relpath(
                                os.path.join(root, file), repo_path)
                            yield {
                                "type": "vulnerability_report",
                                "report_file": rel_path
                            }

    def _process_main_repository(self, repo_path: str) -> Generator[Dict, None, None]:
        """Process main repository content"""
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith('.sol'):
                    rel_path = os.path.relpath(
                        os.path.join(root, file), repo_path)
                    yield {
                        "type": "solidity_file",
                        "file_path": rel_path
                    }

    def get_all_repositories(self) -> List[Dict]:
        """
        Fetch all repositories from the Sherlock Audit organization.
        Returns a list of repository information.
        """
        try:
            org = self.github.get_organization("sherlock-audit")
            repos = []

            # Check rate limit
            rate_limit = self.github.get_rate_limit()
            if rate_limit.core.remaining < 10:  # Ensure we have enough requests
                reset_time = rate_limit.core.reset.timestamp() - datetime.now().timestamp()
                logger.warning(
                    f"GitHub API rate limit low. Resets in {int(reset_time)} seconds")
                if rate_limit.core.remaining == 0:
                    raise Exception("GitHub API rate limit exceeded")

            for repo in org.get_repos():
                try:
                    repo_info = {
                        "name": repo.name,
                        "clone_url": repo.clone_url,
                        "updated_at": repo.updated_at.isoformat() if repo.updated_at else None,
                        "is_judging": repo.name.endswith("-judging")
                    }
                    repos.append(repo_info)
                except Exception as repo_error:
                    logger.error(
                        f"Error processing repository {repo.name}: {str(repo_error)}")
                    continue

            return repos

        except Exception as e:
            logger.error(f"Error fetching repositories from GitHub: {str(e)}")
            return []

    def _process_codebase_repo(self, repo_path: str, repo_name: str) -> Generator[Dict, None, None]:
        """Process a codebase repository, extracting Solidity files"""
        for sol_file in glob.glob(f"{repo_path}/**/*.sol", recursive=True):
            try:
                with open(sol_file, 'r') as f:
                    content = f.read()

                relative_path = os.path.relpath(sol_file, repo_path)
                normalized_content = self.solidity_processor.normalize_solidity_code(
                    content)

                yield {
                    "type": "solidity_file",
                    "repo_name": repo_name,
                    "file_path": relative_path,
                    "content": normalized_content,
                    "raw_content": content
                }
            except Exception as e:
                logger.error(
                    f"Error processing Solidity file {sol_file}: {str(e)}")

    def _process_judging_repo(self, repo_path: str, repo_name: str) -> Generator[Dict, None, None]:
        """Process a judging repository, extracting vulnerability reports"""
        base_repo_name = repo_name.replace("-judging", "")

        for md_file in glob.glob(f"{repo_path}/**/*.md", recursive=True):
            try:
                with open(md_file, 'r') as f:
                    content = f.read()

                # Extract code references and metadata
                metadata = self._extract_report_metadata(content)

                yield {
                    "type": "vulnerability_report",
                    "repo_name": base_repo_name,
                    "report_file": os.path.relpath(md_file, repo_path),
                    "content": content,
                    "metadata": metadata
                }
            except Exception as e:
                logger.error(
                    f"Error processing report file {md_file}: {str(e)}")

    def _extract_report_metadata(self, content: str) -> Dict:
        """Extract metadata from vulnerability report"""
        metadata = {
            "severity": None,
            "title": None,
            "code_references": []
        }

        # Extract severity
        severity_match = re.search(
            r'severity:?\s*(critical|high|medium|low)', content.lower())
        if severity_match:
            metadata["severity"] = severity_match.group(1)

        # Extract title
        title_match = re.search(r'^#\s*(.+)$', content, re.MULTILINE)
        if title_match:
            metadata["title"] = title_match.group(1).strip()

        # Extract code references (files and line numbers)
        code_refs = re.finditer(
            r'(?:File|In):\s*[`"]?([^`"\n]+\.sol)[`"]?(?:[^\n]*?(?:Line|L):\s*(\d+))?', content)
        for ref in code_refs:
            file_path = ref.group(1)
            line_num = ref.group(2) if ref.group(2) else None
            metadata["code_references"].append({
                "file": file_path,
                "line": int(line_num) if line_num else None
            })

        return metadata

    def link_vulnerabilities_to_code(self, vulnerability: Dict, codebase: Dict) -> Dict:
        """
        Link a vulnerability report to its referenced code sections.
        Returns enriched vulnerability data with actual code contexts.
        """
        # TODO: Implement vulnerability-to-code linking
        return {
            **vulnerability,
            "code_contexts": []  # Add extracted code contexts here
        }
