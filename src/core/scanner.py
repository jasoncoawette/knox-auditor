"""
Knox Security Scanner Core Module
Handles file scanning and code analysis
"""
import os
import re
from pathlib import Path
from typing import List, Dict, Any
import ast

class CodeScanner:
    """Scans code files for potential security vulnerabilities"""

    SUPPORTED_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go',
        '.php', '.rb', '.rs', '.cpp', '.c', '.cs', '.sql'
    }

    def __init__(self):
        self.findings = []

    def scan_directory(self, path: str) -> List[Dict[str, Any]]:
        """Scan entire directory for security issues"""
        findings = []
        path_obj = Path(path)

        if not path_obj.exists():
            return [{"error": f"Path does not exist: {path}"}]

        # Scan all supported files
        for file_path in path_obj.rglob('*'):
            if file_path.is_file() and file_path.suffix in self.SUPPORTED_EXTENSIONS:
                file_findings = self.scan_file(str(file_path))
                findings.extend(file_findings)

        return findings

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single file for security issues"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # Basic pattern matching for common vulnerabilities
            findings.extend(self._check_hardcoded_secrets(file_path, content, lines))
            findings.extend(self._check_sql_injection(file_path, content, lines))
            findings.extend(self._check_xss_vulnerabilities(file_path, content, lines))
            findings.extend(self._check_insecure_functions(file_path, content, lines))
            findings.extend(self._check_authentication_issues(file_path, content, lines))

        except Exception as e:
            findings.append({
                "file": file_path,
                "type": "scan_error",
                "severity": "info",
                "message": f"Error scanning file: {str(e)}"
            })

        return findings

    def _check_hardcoded_secrets(self, file_path: str, content: str, lines: List[str]) -> List[Dict]:
        """Check for hardcoded secrets and credentials"""
        findings = []
        patterns = [
            (r'api[_-]?key\s*=\s*["\']([^"\']+)["\']', "API Key"),
            (r'password\s*=\s*["\']([^"\']+)["\']', "Password"),
            (r'secret[_-]?key\s*=\s*["\']([^"\']+)["\']', "Secret Key"),
            (r'token\s*=\s*["\']([^"\']+)["\']', "Token"),
            (r'aws[_-]?access[_-]?key\s*=\s*["\']([^"\']+)["\']', "AWS Access Key"),
            (r'["\'][A-Za-z0-9]{20,}["\']', "Potential Secret"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, secret_type in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it's clearly a placeholder
                    if any(placeholder in line.lower() for placeholder in ['your_', 'example', 'placeholder', 'xxx', 'test']):
                        continue

                    findings.append({
                        "file": file_path,
                        "line": i,
                        "type": "hardcoded_secret",
                        "severity": "critical",
                        "message": f"Potential hardcoded {secret_type} detected",
                        "code": line.strip()
                    })

        return findings

    def _check_sql_injection(self, file_path: str, content: str, lines: List[str]) -> List[Dict]:
        """Check for SQL injection vulnerabilities"""
        findings = []
        patterns = [
            r'execute\s*\(\s*["\'].*%s.*["\'].*%',
            r'execute\s*\(\s*["\'].*\+.*["\']',
            r'executemany\s*\(\s*f["\']',
            r'\.query\s*\(\s*["\'].*\+',
            r'SELECT.*FROM.*WHERE.*\+',
        ]

        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "file": file_path,
                        "line": i,
                        "type": "sql_injection",
                        "severity": "high",
                        "message": "Potential SQL injection vulnerability - use parameterized queries",
                        "code": line.strip()
                    })

        return findings

    def _check_xss_vulnerabilities(self, file_path: str, content: str, lines: List[str]) -> List[Dict]:
        """Check for XSS vulnerabilities"""
        findings = []
        patterns = [
            r'innerHTML\s*=',
            r'dangerouslySetInnerHTML',
            r'document\.write\s*\(',
            r'eval\s*\(',
            r'\.html\s*\(\s*[^"\']',
        ]

        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "file": file_path,
                        "line": i,
                        "type": "xss_vulnerability",
                        "severity": "high",
                        "message": "Potential XSS vulnerability - sanitize user input",
                        "code": line.strip()
                    })

        return findings

    def _check_insecure_functions(self, file_path: str, content: str, lines: List[str]) -> List[Dict]:
        """Check for insecure function usage"""
        findings = []
        patterns = [
            (r'pickle\.loads?\s*\(', "Insecure deserialization with pickle"),
            (r'yaml\.load\s*\((?!.*Loader=)', "Unsafe YAML loading"),
            (r'subprocess\.call\s*\(.*shell\s*=\s*True', "Command injection risk"),
            (r'os\.system\s*\(', "Command injection risk"),
            (r'exec\s*\(', "Dangerous exec() usage"),
            (r'md5\s*\(', "Weak hashing algorithm MD5"),
            (r'sha1\s*\(', "Weak hashing algorithm SHA1"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, message in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "file": file_path,
                        "line": i,
                        "type": "insecure_function",
                        "severity": "high",
                        "message": message,
                        "code": line.strip()
                    })

        return findings

    def _check_authentication_issues(self, file_path: str, content: str, lines: List[str]) -> List[Dict]:
        """Check for authentication and authorization issues"""
        findings = []
        patterns = [
            (r'verify\s*=\s*False', "SSL certificate verification disabled"),
            (r'DEBUG\s*=\s*True', "Debug mode enabled in production"),
            (r'ALLOWED_HOSTS\s*=\s*\[\s*["\']?\*["\']?\s*\]', "Allowed hosts set to wildcard"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, message in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "file": file_path,
                        "line": i,
                        "type": "authentication_issue",
                        "severity": "medium",
                        "message": message,
                        "code": line.strip()
                    })

        return findings
