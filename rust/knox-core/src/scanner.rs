//! High-performance file scanner with parallel processing
//!
//! Provides fast directory traversal and file scanning using rayon
//! for parallel processing and memory-mapped files for efficiency

use crate::matcher::{Match, PatternMatcher};
use memmap2::Mmap;
use pyo3::prelude::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct ScanResult {
    #[pyo3(get)]
    pub file_path: String,
    #[pyo3(get)]
    pub matches: Vec<Match>,
    #[pyo3(get)]
    pub scan_time_ms: u64,
    #[pyo3(get)]
    pub file_size: u64,
}

#[pymethods]
impl ScanResult {
    fn __repr__(&self) -> String {
        format!(
            "ScanResult(file={}, matches={}, time={}ms)",
            self.file_path,
            self.matches.len(),
            self.scan_time_ms
        )
    }
}

/// Fast file scanner with parallel processing
#[pyclass]
pub struct FastScanner {
    matcher: PatternMatcher,
    extensions: Vec<String>,
    max_file_size: u64,
}

#[pymethods]
impl FastScanner {
    #[new]
    pub fn new(max_file_size_mb: Option<u64>) -> Self {
        FastScanner {
            matcher: PatternMatcher::new(),
            extensions: vec![
                ".py".to_string(),
                ".js".to_string(),
                ".ts".to_string(),
                ".jsx".to_string(),
                ".tsx".to_string(),
                ".rs".to_string(),
                ".go".to_string(),
                ".java".to_string(),
                ".php".to_string(),
                ".rb".to_string(),
                ".c".to_string(),
                ".cpp".to_string(),
                ".cs".to_string(),
            ],
            max_file_size: max_file_size_mb.unwrap_or(10) * 1024 * 1024,
        }
    }

    /// Scan a single file
    pub fn scan_file_sync(&mut self, path: String) -> PyResult<ScanResult> {
        let start = std::time::Instant::now();
        let path_obj = Path::new(&path);

        if !path_obj.exists() {
            return Err(pyo3::exceptions::PyFileNotFoundError::new_err(format!(
                "File not found: {}",
                path
            )));
        }

        let metadata = std::fs::metadata(path_obj)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let file_size = metadata.len();

        if file_size > self.max_file_size {
            return Ok(ScanResult {
                file_path: path,
                matches: vec![],
                scan_time_ms: 0,
                file_size,
            });
        }

        let matches = if file_size > 0 {
            match self.scan_file_mmap(path_obj) {
                Ok(m) => m,
                Err(_) => self.scan_file_normal(path_obj)?,
            }
        } else {
            vec![]
        };

        Ok(ScanResult {
            file_path: path,
            matches,
            scan_time_ms: start.elapsed().as_millis() as u64,
            file_size,
        })
    }

    /// Add a supported file extension
    pub fn add_extension(&mut self, ext: String) {
        if !self.extensions.contains(&ext) {
            self.extensions.push(ext);
        }
    }

    /// Get list of supported extensions
    pub fn get_extensions(&self) -> Vec<String> {
        self.extensions.clone()
    }
}

impl FastScanner {
    /// Scan file using memory mapping for better performance
    fn scan_file_mmap(&mut self, path: &Path) -> Result<Vec<Match>, std::io::Error> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let content = std::str::from_utf8(&mmap).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;

        Ok(self.matcher.match_content(content))
    }

    /// Fallback method for scanning files normally
    fn scan_file_normal(&mut self, path: &Path) -> PyResult<Vec<Match>> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        Ok(self.matcher.match_content(&content))
    }

    /// Check if file should be scanned based on extension
    fn should_scan(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            let ext_str = format!(".{}", ext.to_string_lossy());
            self.extensions.contains(&ext_str)
        } else {
            false
        }
    }
}

/// Scan a single file (convenience function for Python)
#[pyfunction]
pub fn scan_file(path: String) -> PyResult<ScanResult> {
    let mut scanner = FastScanner::new(None);
    scanner.scan_file_sync(path)
}

/// Scan a directory recursively with parallel processing
#[pyfunction]
pub fn scan_directory(
    path: String,
    max_depth: Option<usize>,
    parallel: Option<bool>,
) -> PyResult<Vec<ScanResult>> {
    let path_obj = Path::new(&path);

    if !path_obj.exists() {
        return Err(pyo3::exceptions::PyFileNotFoundError::new_err(format!(
            "Directory not found: {}",
            path
        )));
    }

    let scanner = FastScanner::new(None);
    let extensions = scanner.extensions.clone();

    // Collect all files to scan
    let mut walker = WalkDir::new(path_obj);
    if let Some(depth) = max_depth {
        walker = walker.max_depth(depth);
    }

    let files: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            if let Some(ext) = e.path().extension() {
                let ext_str = format!(".{}", ext.to_string_lossy());
                extensions.contains(&ext_str)
            } else {
                false
            }
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    // Scan files (parallel or sequential)
    let results = if parallel.unwrap_or(true) && files.len() > 1 {
        files
            .par_iter()
            .filter_map(|file_path| {
                let mut scanner = FastScanner::new(None);
                scanner
                    .scan_file_sync(file_path.to_string_lossy().to_string())
                    .ok()
            })
            .collect()
    } else {
        let mut scanner = FastScanner::new(None);
        files
            .iter()
            .filter_map(|file_path| {
                scanner
                    .scan_file_sync(file_path.to_string_lossy().to_string())
                    .ok()
            })
            .collect()
    };

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::write;
    use tempfile::TempDir;

    #[test]
    fn test_scan_file_with_vulnerabilities() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.py");
        write(
            &file_path,
            r#"
API_KEY = "sk-1234567890abcdefghij"
password = "admin123"
query = "SELECT * FROM users WHERE id = " + user_id
"#,
        )
        .unwrap();

        let mut scanner = FastScanner::new(None);
        let result = scanner
            .scan_file_sync(file_path.to_string_lossy().to_string())
            .unwrap();

        assert!(result.matches.len() >= 2);
    }

    #[test]
    fn test_scan_directory() {
        let temp_dir = TempDir::new().unwrap();

        write(
            temp_dir.path().join("file1.py"),
            "API_KEY = 'sk-123456789012345678901234'",
        )
        .unwrap();
        write(
            temp_dir.path().join("file2.py"),
            "password = 'secret123'",
        )
        .unwrap();

        let results =
            scan_directory(temp_dir.path().to_string_lossy().to_string(), None, Some(false))
                .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|r| r.matches.len() > 0));
    }
}
