"""
Knox GitHub Integration Module
Handles GitHub API interactions for PR auditing
"""
import os
import requests
from typing import Dict, List, Any

class GitHubIntegration:
    """GitHub API integration for security audits"""

    def __init__(self, token: str = None):
        self.token = token or os.getenv('GITHUB_TOKEN')
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {self.token}" if self.token else "",
            "Accept": "application/vnd.github.v3+json"
        }

    def get_pr_files(self, owner: str, repo: str, pr_number: int) -> List[Dict[str, Any]]:
        """Get files changed in a pull request"""
        if not self.token:
            return []

        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching PR files: {e}")
            return []

    def get_file_content(self, owner: str, repo: str, file_path: str, ref: str = "main") -> str:
        """Get content of a specific file from repository"""
        if not self.token:
            return ""

        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{file_path}"

        try:
            response = requests.get(url, headers=self.headers, params={"ref": ref})
            response.raise_for_status()
            import base64
            content = base64.b64decode(response.json()['content']).decode('utf-8')
            return content
        except Exception as e:
            print(f"Error fetching file content: {e}")
            return ""

    def post_pr_comment(self, owner: str, repo: str, pr_number: int, comment: str) -> bool:
        """Post a comment on a pull request"""
        if not self.token:
            return False

        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"

        try:
            response = requests.post(
                url,
                headers=self.headers,
                json={"body": comment}
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Error posting PR comment: {e}")
            return False

    def post_inline_comment(self, owner: str, repo: str, pr_number: int,
                          commit_id: str, file_path: str, line: int, comment: str) -> bool:
        """Post an inline comment on a specific line in a PR"""
        if not self.token:
            return False

        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/comments"

        try:
            response = requests.post(
                url,
                headers=self.headers,
                json={
                    "body": comment,
                    "commit_id": commit_id,
                    "path": file_path,
                    "line": line,
                    "side": "RIGHT"
                }
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Error posting inline comment: {e}")
            return False

    def create_check_run(self, owner: str, repo: str, commit_sha: str,
                        name: str, conclusion: str, output: Dict) -> bool:
        """Create a check run for a commit"""
        if not self.token:
            return False

        url = f"{self.base_url}/repos/{owner}/{repo}/check-runs"

        try:
            response = requests.post(
                url,
                headers={**self.headers, "Accept": "application/vnd.github.v3+json"},
                json={
                    "name": name,
                    "head_sha": commit_sha,
                    "status": "completed",
                    "conclusion": conclusion,
                    "output": output
                }
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Error creating check run: {e}")
            return False
