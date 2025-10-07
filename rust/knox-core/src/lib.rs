//! Knox Core - High-performance security scanning engine
//!
//! This module provides fast pattern matching and code parsing
//! for security vulnerability detection.

pub mod matcher;
pub mod parser;
pub mod scanner;

use pyo3::prelude::*;

/// Python module initialization
#[pymodule]
fn knox_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<matcher::PatternMatcher>()?;
    m.add_class::<scanner::FastScanner>()?;
    m.add_function(wrap_pyfunction!(scanner::scan_file, m)?)?;
    m.add_function(wrap_pyfunction!(scanner::scan_directory, m)?)?;
    Ok(())
}
