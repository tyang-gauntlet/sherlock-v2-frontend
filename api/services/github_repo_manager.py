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
    def __init__(self, github_token: str, base_dir: str = "repositories"):
        """
        Initialize the GitHub repository manager.

        Args:
            github_token (str): GitHub personal access token
            base_dir (str): Base directory to store repositories
        """
        self.github = Github(github_token)
        self.base_dir = base_dir
        self.tracking_file = os.path.join(base_dir, "repo_tracking.json")
        self.org_name = "sherlock-audit"
        self.solidity_processor = SolidityProcessor()

        # Create base directory if it doesn't exist
        os.makedirs(base_dir, exist_ok=True)

        # Initialize or load tracking data
        self.tracking_data = self._load_tracking_data()

    def _load_tracking_data(self) -> Dict:
        """Load or initialize repository tracking data."""
        if os.path.exists(self.tracking_file):
            with open(self.tracking_file, 'r') as f:
                return json.load(f)
        return {
            "codebase_repos": {},
            "judging_repos": {},
            "last_update": None
        }

    def _save_tracking_data(self):
        """Save repository tracking data."""
        with open(self.tracking_file, 'w') as f:
            json.dump(self.tracking_data, f, indent=2)

    def get_all_repositories(self) -> List[Dict]:
        """
        Fetch all repositories from the Sherlock Audit organization.
        Returns a list of repository information.
        """
        org = self.github.get_organization(self.org_name)
        repos = []

        for repo in org.get_repos():
            repo_info = {
                "name": repo.name,
                "clone_url": repo.clone_url,
                "updated_at": repo.updated_at.isoformat(),
                "is_judging": repo.name.endswith("-judging")
            }
            repos.append(repo_info)

        return repos

    def clone_repository(self, repo_info: Dict, target_path: str) -> bool:
        """Clone a repository to a specific path"""
        try:
            if os.path.exists(target_path):
                shutil.rmtree(target_path)

            os.makedirs(target_path, exist_ok=True)
            Repo.clone_from(repo_info["clone_url"], target_path)
            return True

        except Exception as e:
            logger.error(
                f"Error cloning repository {repo_info['name']}: {str(e)}")
            return False

    def process_repository_content(self, repo_info: Dict, repo_path: str) -> Generator[Dict, None, None]:
        """Process repository content based on type (codebase or audit)"""
        try:
            if repo_info["is_judging"]:
                yield from self._process_judging_repo(repo_path, repo_info["name"])
            else:
                yield from self._process_codebase_repo(repo_path, repo_info["name"])

        except Exception as e:
            logger.error(
                f"Error processing repository {repo_info['name']}: {str(e)}")

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
