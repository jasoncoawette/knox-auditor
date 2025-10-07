# Knox Core - Rust Performance Module

High-performance security scanning engine written in Rust for the Knox security auditor.

## Features

- **Fast Pattern Matching**: Uses Aho-Corasick algorithm for multi-pattern matching
- **Parallel Processing**: Leverages rayon for concurrent file scanning
- **Memory-Mapped I/O**: Efficient file reading using mmap for large files
- **Python Bindings**: Full PyO3 integration for seamless Python interop
- **Language-Aware Parsing**: Extracts functions, imports, and string literals

## Components

### Pattern Matcher (`matcher.rs`)
- Multi-pattern matching engine
- Pre-configured security patterns
- Support for custom patterns
- Regex-based matching with caching

### Code Parser (`parser.rs`)
- Function extraction (Python, JavaScript, Rust)
- Import statement analysis
- String literal extraction
- Code complexity metrics

### Fast Scanner (`scanner.rs`)
- Parallel directory traversal
- Memory-mapped file scanning
- Configurable file size limits
- Multi-language support

## Building

```bash
# Build release version
cargo build --release

# Run tests
cargo test

# Build Python wheel
maturin develop --release
```

## Python Usage

```python
import knox_core

# Scan a single file
result = knox_core.scan_file("/path/to/file.py")
print(f"Found {len(result.matches)} issues")

# Scan directory in parallel
results = knox_core.scan_directory("/path/to/repo", parallel=True)
for result in results:
    if result.matches:
        print(f"{result.file_path}: {len(result.matches)} issues")

# Use pattern matcher directly
matcher = knox_core.PatternMatcher()
matches = matcher.match_content("API_KEY = 'sk-1234567890'")

# Parse code
parser = knox_core.CodeParser("python")
functions = parser.extract_functions(code)
imports = parser.extract_imports(code)
```

## Performance

- **Scan Speed**: ~5000 lines/second on typical codebases
- **Memory Efficiency**: Uses mmap for files > 1MB
- **Parallelization**: Scales with CPU cores
- **Pattern Matching**: O(n) complexity with Aho-Corasick

## Security Patterns

Built-in patterns detect:
- Hardcoded API keys and secrets
- SQL injection vulnerabilities
- Command injection risks
- Weak cryptographic algorithms
- Insecure deserialization
- XSS vulnerabilities
- SSL verification issues
- Debug mode configurations

## Development

### Adding New Patterns

```rust
use knox_core::matcher::SecurityPattern;

let pattern = SecurityPattern::new(
    "custom_pattern".to_string(),
    r"dangerous_function\(".to_string(),
    "high".to_string(),
    "custom".to_string(),
    "Description here".to_string(),
);

matcher.add_pattern(pattern);
```

### Testing

```bash
cargo test --lib          # Run unit tests
cargo test --release      # Run with optimizations
cargo bench              # Run benchmarks
```

## License

MIT
