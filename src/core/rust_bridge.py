"""
Knox Rust Bridge Module
Provides Python interface to high-performance Rust scanning engine
"""
import sys
from typing import List, Dict, Any, Optional

# Try to import Rust module, fallback to Python if not available
RUST_AVAILABLE = False
try:
    import knox_core
    RUST_AVAILABLE = True
except ImportError:
    pass


class RustScanner:
    """Wrapper for Rust-based fast scanner with fallback to Python"""

    def __init__(self, use_rust: bool = True, max_file_size_mb: int = 10):
        self.use_rust = use_rust and RUST_AVAILABLE
        self.max_file_size_mb = max_file_size_mb

        if self.use_rust:
            self._rust_scanner = knox_core.FastScanner(max_file_size_mb)
        else:
            self._rust_scanner = None

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a single file for security vulnerabilities"""
        if self.use_rust:
            result = self._rust_scanner.scan_file_sync(file_path)
            return {
                "file_path": result.file_path,
                "matches": [self._convert_match(m) for m in result.matches],
                "scan_time_ms": result.scan_time_ms,
                "file_size": result.file_size,
            }
        else:
            # Fallback to Python scanner
            from .scanner import CodeScanner

            scanner = CodeScanner()
            findings = scanner.scan_file(file_path)
            return {
                "file_path": file_path,
                "matches": findings,
                "scan_time_ms": 0,
                "file_size": 0,
            }

    def scan_directory(
        self, path: str, max_depth: Optional[int] = None, parallel: bool = True
    ) -> List[Dict[str, Any]]:
        """Scan directory recursively"""
        if self.use_rust:
            results = knox_core.scan_directory(path, max_depth, parallel)
            return [
                {
                    "file_path": r.file_path,
                    "matches": [self._convert_match(m) for m in r.matches],
                    "scan_time_ms": r.scan_time_ms,
                    "file_size": r.file_size,
                }
                for r in results
            ]
        else:
            # Fallback to Python scanner
            from .scanner import CodeScanner

            scanner = CodeScanner()
            findings = scanner.scan_directory(path)

            # Group findings by file
            files = {}
            for finding in findings:
                file_path = finding.get("file", "unknown")
                if file_path not in files:
                    files[file_path] = []
                files[file_path].append(finding)

            return [
                {
                    "file_path": file_path,
                    "matches": matches,
                    "scan_time_ms": 0,
                    "file_size": 0,
                }
                for file_path, matches in files.items()
            ]

    def _convert_match(self, rust_match) -> Dict[str, Any]:
        """Convert Rust match to Python dict"""
        return {
            "line": rust_match.line_number,
            "column": rust_match.column,
            "type": rust_match.pattern_name,
            "severity": rust_match.severity,
            "code": rust_match.matched_text,
            "category": rust_match.category,
        }

    @property
    def is_rust_available(self) -> bool:
        """Check if Rust backend is available"""
        return RUST_AVAILABLE


class RustPatternMatcher:
    """Wrapper for Rust pattern matcher"""

    def __init__(self):
        if RUST_AVAILABLE:
            self._matcher = knox_core.PatternMatcher()
        else:
            self._matcher = None

    def match_content(self, content: str) -> List[Dict[str, Any]]:
        """Match patterns in content"""
        if self._matcher:
            matches = self._matcher.match_content(content)
            return [
                {
                    "line_number": m.line_number,
                    "column": m.column,
                    "pattern_name": m.pattern_name,
                    "severity": m.severity,
                    "matched_text": m.matched_text,
                    "category": m.category,
                }
                for m in matches
            ]
        else:
            return []

    def add_pattern(
        self,
        name: str,
        pattern: str,
        severity: str,
        category: str,
        description: str,
    ):
        """Add custom security pattern"""
        if self._matcher:
            rust_pattern = knox_core.SecurityPattern(
                name, pattern, severity, category, description
            )
            self._matcher.add_pattern(rust_pattern)


class RustCodeParser:
    """Wrapper for Rust code parser"""

    def __init__(self, language: str = "python"):
        if RUST_AVAILABLE:
            self._parser = knox_core.CodeParser(language)
        else:
            self._parser = None
            self.language = language

    def extract_functions(self, content: str) -> List[Dict[str, Any]]:
        """Extract function definitions from code"""
        if self._parser:
            functions = self._parser.extract_functions(content)
            return [
                {
                    "name": f.name,
                    "line_number": f.line_number,
                    "parameters": f.parameters,
                    "is_async": f.is_async,
                }
                for f in functions
            ]
        else:
            return []

    def extract_imports(self, content: str) -> List[Dict[str, Any]]:
        """Extract import statements from code"""
        if self._parser:
            imports = self._parser.extract_imports(content)
            return [
                {
                    "module": i.module,
                    "items": i.items,
                    "line_number": i.line_number,
                    "is_wildcard": i.is_wildcard,
                }
                for i in imports
            ]
        else:
            return []

    def extract_strings(self, content: str) -> List[Dict[str, Any]]:
        """Extract string literals from code"""
        if self._parser:
            strings = self._parser.extract_strings(content)
            return [
                {
                    "value": s.value,
                    "line_number": s.line_number,
                    "is_multiline": s.is_multiline,
                    "quote_type": s.quote_type,
                }
                for s in strings
            ]
        else:
            return []

    def analyze_complexity(self, content: str) -> Dict[str, int]:
        """Analyze code complexity metrics"""
        if self._parser:
            return self._parser.analyze_complexity(content)
        else:
            return {
                "total_lines": len(content.split("\n")),
                "code_lines": 0,
                "functions": 0,
                "imports": 0,
            }


def is_rust_available() -> bool:
    """Check if Rust performance modules are available"""
    return RUST_AVAILABLE


def get_rust_info() -> Dict[str, Any]:
    """Get information about Rust backend"""
    return {
        "available": RUST_AVAILABLE,
        "module": "knox_core" if RUST_AVAILABLE else None,
        "features": [
            "fast_scanning",
            "pattern_matching",
            "code_parsing",
            "parallel_processing",
        ]
        if RUST_AVAILABLE
        else [],
    }
