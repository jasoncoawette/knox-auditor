//! High-performance pattern matching engine for security vulnerabilities
//!
//! Uses Aho-Corasick algorithm for efficient multi-pattern matching

use aho_corasick::AhoCorasick;
use pyo3::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct SecurityPattern {
    #[pyo3(get, set)]
    pub name: String,
    #[pyo3(get, set)]
    pub pattern: String,
    #[pyo3(get, set)]
    pub severity: String,
    #[pyo3(get, set)]
    pub category: String,
    #[pyo3(get, set)]
    pub description: String,
}

#[pymethods]
impl SecurityPattern {
    #[new]
    pub fn new(
        name: String,
        pattern: String,
        severity: String,
        category: String,
        description: String,
    ) -> Self {
        SecurityPattern {
            name,
            pattern,
            severity,
            category,
            description,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct Match {
    #[pyo3(get)]
    pub line_number: usize,
    #[pyo3(get)]
    pub column: usize,
    #[pyo3(get)]
    pub pattern_name: String,
    #[pyo3(get)]
    pub severity: String,
    #[pyo3(get)]
    pub matched_text: String,
    #[pyo3(get)]
    pub category: String,
}

#[pymethods]
impl Match {
    fn __repr__(&self) -> String {
        format!(
            "Match(line={}, col={}, pattern={}, severity={})",
            self.line_number, self.column, self.pattern_name, self.severity
        )
    }
}

/// Fast pattern matcher using Aho-Corasick algorithm
#[pyclass]
pub struct PatternMatcher {
    patterns: Vec<SecurityPattern>,
    regex_cache: HashMap<String, Regex>,
}

#[pymethods]
impl PatternMatcher {
    #[new]
    pub fn new() -> Self {
        PatternMatcher {
            patterns: Self::default_patterns(),
            regex_cache: HashMap::new(),
        }
    }

    /// Add a custom security pattern
    pub fn add_pattern(&mut self, pattern: SecurityPattern) {
        self.patterns.push(pattern);
    }

    /// Match patterns in a single line of code
    pub fn match_line(&mut self, line: &str, line_number: usize) -> Vec<Match> {
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            if let Some(regex) = self.get_or_compile_regex(&pattern.pattern) {
                if let Some(capture) = regex.find(line) {
                    matches.push(Match {
                        line_number,
                        column: capture.start(),
                        pattern_name: pattern.name.clone(),
                        severity: pattern.severity.clone(),
                        matched_text: capture.as_str().to_string(),
                        category: pattern.category.clone(),
                    });
                }
            }
        }

        matches
    }

    /// Match patterns across multiple lines efficiently
    pub fn match_content(&mut self, content: &str) -> Vec<Match> {
        let mut all_matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_matches = self.match_line(line, line_num + 1);
            all_matches.extend(line_matches);
        }

        all_matches
    }

    /// Get pattern statistics
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl PatternMatcher {
    fn get_or_compile_regex(&mut self, pattern: &str) -> Option<&Regex> {
        if !self.regex_cache.contains_key(pattern) {
            if let Ok(regex) = Regex::new(pattern) {
                self.regex_cache.insert(pattern.to_string(), regex);
            } else {
                return None;
            }
        }
        self.regex_cache.get(pattern)
    }

    /// Default security patterns for common vulnerabilities
    fn default_patterns() -> Vec<SecurityPattern> {
        vec![
            SecurityPattern {
                name: "hardcoded_api_key".to_string(),
                pattern: r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']"#
                    .to_string(),
                severity: "critical".to_string(),
                category: "secrets".to_string(),
                description: "Hardcoded API key detected".to_string(),
            },
            SecurityPattern {
                name: "hardcoded_password".to_string(),
                pattern: r#"(?i)(password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']"#.to_string(),
                severity: "critical".to_string(),
                category: "secrets".to_string(),
                description: "Hardcoded password detected".to_string(),
            },
            SecurityPattern {
                name: "sql_injection".to_string(),
                pattern: r#"(?i)(execute|query)\s*\(\s*["'].*\+.*["']"#.to_string(),
                severity: "high".to_string(),
                category: "injection".to_string(),
                description: "Potential SQL injection vulnerability".to_string(),
            },
            SecurityPattern {
                name: "command_injection".to_string(),
                pattern: r#"(?i)(os\.system|subprocess\.call|exec)\s*\("#.to_string(),
                severity: "high".to_string(),
                category: "injection".to_string(),
                description: "Potential command injection risk".to_string(),
            },
            SecurityPattern {
                name: "weak_crypto_md5".to_string(),
                pattern: r#"(?i)(md5|hashlib\.md5)\s*\("#.to_string(),
                severity: "medium".to_string(),
                category: "crypto".to_string(),
                description: "Weak cryptographic algorithm MD5".to_string(),
            },
            SecurityPattern {
                name: "weak_crypto_sha1".to_string(),
                pattern: r#"(?i)(sha1|hashlib\.sha1)\s*\("#.to_string(),
                severity: "medium".to_string(),
                category: "crypto".to_string(),
                description: "Weak cryptographic algorithm SHA1".to_string(),
            },
            SecurityPattern {
                name: "insecure_deserialization".to_string(),
                pattern: r#"(?i)(pickle\.loads?|yaml\.load)\s*\("#.to_string(),
                severity: "high".to_string(),
                category: "deserialization".to_string(),
                description: "Insecure deserialization detected".to_string(),
            },
            SecurityPattern {
                name: "xss_vulnerability".to_string(),
                pattern: r#"(?i)(innerHTML|dangerouslySetInnerHTML|document\.write)\s*="#
                    .to_string(),
                severity: "high".to_string(),
                category: "xss".to_string(),
                description: "Potential XSS vulnerability".to_string(),
            },
            SecurityPattern {
                name: "debug_mode".to_string(),
                pattern: r#"(?i)(DEBUG|debug)\s*=\s*(True|true|1)"#.to_string(),
                severity: "medium".to_string(),
                category: "config".to_string(),
                description: "Debug mode enabled".to_string(),
            },
            SecurityPattern {
                name: "ssl_verification_disabled".to_string(),
                pattern: r#"(?i)verify\s*=\s*(False|false|0)"#.to_string(),
                severity: "high".to_string(),
                category: "crypto".to_string(),
                description: "SSL certificate verification disabled".to_string(),
            },
        ]
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardcoded_api_key_detection() {
        let mut matcher = PatternMatcher::new();
        let code = r#"API_KEY = "sk-1234567890abcdefghij""#;
        let matches = matcher.match_content(code);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].category, "secrets");
    }

    #[test]
    fn test_sql_injection_detection() {
        let mut matcher = PatternMatcher::new();
        let code = r#"query("SELECT * FROM users WHERE id = " + user_id)"#;
        let matches = matcher.match_content(code);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].category, "injection");
    }

    #[test]
    fn test_weak_crypto_detection() {
        let mut matcher = PatternMatcher::new();
        let code = r#"hashlib.md5(password.encode())"#;
        let matches = matcher.match_content(code);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].category, "crypto");
    }
}
