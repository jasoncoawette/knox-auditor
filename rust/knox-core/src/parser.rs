//! Fast code parsing utilities for security analysis
//!
//! Provides language-aware parsing for extracting security-relevant
//! code constructs like function calls, imports, and string literals

use pyo3::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct ParsedFunction {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub line_number: usize,
    #[pyo3(get)]
    pub parameters: Vec<String>,
    #[pyo3(get)]
    pub is_async: bool,
}

#[pymethods]
impl ParsedFunction {
    fn __repr__(&self) -> String {
        format!(
            "Function(name={}, line={}, params={:?})",
            self.name, self.line_number, self.parameters
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct ParsedImport {
    #[pyo3(get)]
    pub module: String,
    #[pyo3(get)]
    pub items: Vec<String>,
    #[pyo3(get)]
    pub line_number: usize,
    #[pyo3(get)]
    pub is_wildcard: bool,
}

#[pymethods]
impl ParsedImport {
    fn __repr__(&self) -> String {
        format!(
            "Import(module={}, items={:?}, line={})",
            self.module, self.items, self.line_number
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct StringLiteral {
    #[pyo3(get)]
    pub value: String,
    #[pyo3(get)]
    pub line_number: usize,
    #[pyo3(get)]
    pub is_multiline: bool,
    #[pyo3(get)]
    pub quote_type: String,
}

/// Code parser for extracting security-relevant constructs
#[pyclass]
pub struct CodeParser {
    language: String,
    function_regex: HashMap<String, Regex>,
    import_regex: HashMap<String, Regex>,
}

#[pymethods]
impl CodeParser {
    #[new]
    pub fn new(language: Option<String>) -> Self {
        let lang = language.unwrap_or_else(|| "python".to_string());
        let mut parser = CodeParser {
            language: lang.clone(),
            function_regex: HashMap::new(),
            import_regex: HashMap::new(),
        };
        parser.compile_patterns(&lang);
        parser
    }

    /// Extract all function definitions from code
    pub fn extract_functions(&self, content: &str) -> Vec<ParsedFunction> {
        let mut functions = Vec::new();

        if let Some(regex) = self.function_regex.get(&self.language) {
            for (line_num, line) in content.lines().enumerate() {
                if let Some(captures) = regex.captures(line) {
                    let is_async = captures
                        .get(1)
                        .map(|m| m.as_str().contains("async"))
                        .unwrap_or(false);
                    let name = captures.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
                    let params_str = captures.get(3).map(|m| m.as_str()).unwrap_or("");
                    let parameters = Self::parse_parameters(params_str);

                    functions.push(ParsedFunction {
                        name,
                        line_number: line_num + 1,
                        parameters,
                        is_async,
                    });
                }
            }
        }

        functions
    }

    /// Extract all import statements from code
    pub fn extract_imports(&self, content: &str) -> Vec<ParsedImport> {
        let mut imports = Vec::new();

        if let Some(regex) = self.import_regex.get(&self.language) {
            for (line_num, line) in content.lines().enumerate() {
                if let Some(captures) = regex.captures(line) {
                    let module = captures.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let items_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                    let is_wildcard = items_str.contains('*');
                    let items = if is_wildcard {
                        vec!["*".to_string()]
                    } else {
                        items_str
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    };

                    imports.push(ParsedImport {
                        module,
                        items,
                        line_number: line_num + 1,
                        is_wildcard,
                    });
                }
            }
        }

        imports
    }

    /// Extract all string literals from code
    pub fn extract_strings(&self, content: &str) -> Vec<StringLiteral> {
        let mut strings = Vec::new();
        let string_regex = Regex::new(r#"(['"])((?:[^\1\\]|\\.)*)(\1)"#).unwrap();

        for (line_num, line) in content.lines().enumerate() {
            for capture in string_regex.captures_iter(line) {
                let quote_type = capture.get(1).map(|m| m.as_str()).unwrap_or("\"");
                let value = capture.get(2).map(|m| m.as_str()).unwrap_or("");

                strings.push(StringLiteral {
                    value: value.to_string(),
                    line_number: line_num + 1,
                    is_multiline: false,
                    quote_type: quote_type.to_string(),
                });
            }
        }

        strings
    }

    /// Analyze code complexity
    pub fn analyze_complexity(&self, content: &str) -> PyResult<HashMap<String, usize>> {
        let mut metrics = HashMap::new();

        metrics.insert("total_lines".to_string(), content.lines().count());
        metrics.insert(
            "code_lines".to_string(),
            content
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .count(),
        );
        metrics.insert("functions".to_string(), self.extract_functions(content).len());
        metrics.insert("imports".to_string(), self.extract_imports(content).len());

        Ok(metrics)
    }
}

impl CodeParser {
    fn compile_patterns(&mut self, language: &str) {
        match language {
            "python" => {
                self.function_regex.insert(
                    language.to_string(),
                    Regex::new(r"^\s*(async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)")
                        .unwrap(),
                );
                self.import_regex.insert(
                    language.to_string(),
                    Regex::new(r"^\s*(?:from\s+([a-zA-Z0-9_.]+)\s+)?import\s+(.+)")
                        .unwrap(),
                );
            }
            "javascript" | "typescript" => {
                self.function_regex.insert(
                    language.to_string(),
                    Regex::new(
                        r"^\s*(async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)",
                    )
                    .unwrap(),
                );
                self.import_regex.insert(
                    language.to_string(),
                    Regex::new(r"^\s*import\s+(?:\{([^}]+)\}|([a-zA-Z_$][a-zA-Z0-9_$]*))\s+from")
                        .unwrap(),
                );
            }
            "rust" => {
                self.function_regex.insert(
                    language.to_string(),
                    Regex::new(r"^\s*(async\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)")
                        .unwrap(),
                );
                self.import_regex.insert(
                    language.to_string(),
                    Regex::new(r"^\s*use\s+([a-zA-Z0-9_:]+)(?:::\{([^}]+)\})?").unwrap(),
                );
            }
            _ => {}
        }
    }

    fn parse_parameters(params_str: &str) -> Vec<String> {
        params_str
            .split(',')
            .map(|p| {
                p.trim()
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string()
            })
            .filter(|s| !s.is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_function_extraction() {
        let parser = CodeParser::new(Some("python".to_string()));
        let code = r#"
def hello_world(name, age=25):
    print(f"Hello {name}")

async def fetch_data(url):
    return await request(url)
"#;
        let functions = parser.extract_functions(code);
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "hello_world");
        assert_eq!(functions[0].parameters.len(), 2);
        assert!(functions[1].is_async);
    }

    #[test]
    fn test_python_import_extraction() {
        let parser = CodeParser::new(Some("python".to_string()));
        let code = r#"
import os
from pathlib import Path
from typing import List, Dict
"#;
        let imports = parser.extract_imports(code);
        assert!(imports.len() >= 2);
    }

    #[test]
    fn test_string_extraction() {
        let parser = CodeParser::new(None);
        let code = r#"api_key = "sk-1234567890""#;
        let strings = parser.extract_strings(code);
        assert!(!strings.is_empty());
        assert!(strings[0].value.contains("sk-"));
    }
}
