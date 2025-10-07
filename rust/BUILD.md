# Building Knox Rust Components

This guide explains how to build and integrate the Rust performance modules with Knox.

## Prerequisites

- Rust 1.70 or higher
- Python 3.8 or higher
- maturin (Python package for building Rust extensions)

## Installation

### 1. Install Rust

```bash
# Install Rust using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add to PATH
source $HOME/.cargo/env
```

### 2. Install maturin

```bash
pip install maturin
```

## Building

### Development Build

```bash
cd rust/knox-core
maturin develop
```

This builds the Rust module and installs it in your current Python environment.

### Release Build

```bash
cd rust/knox-core
maturin develop --release
```

### Build Python Wheel

```bash
cd rust/knox-core
maturin build --release
```

The wheel file will be in `target/wheels/`.

## Testing

### Run Rust Tests

```bash
cd rust/knox-core
cargo test
```

### Run with Coverage

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

## Integration with Knox

Once built, the Rust module can be used through the Python bridge:

```python
from src.core.rust_bridge import RustScanner, is_rust_available

# Check if Rust is available
if is_rust_available():
    print("Rust acceleration enabled!")
    scanner = RustScanner(use_rust=True)
else:
    print("Using Python fallback")
    scanner = RustScanner(use_rust=False)

# Scan files
results = scanner.scan_directory("/path/to/code")
```

## Performance Comparison

```python
import time
from src.core.rust_bridge import RustScanner
from src.core.scanner import CodeScanner

# Rust scanner
rust_scanner = RustScanner(use_rust=True)
start = time.time()
rust_results = rust_scanner.scan_directory("./src")
rust_time = time.time() - start

# Python scanner
py_scanner = CodeScanner()
start = time.time()
py_results = py_scanner.scan_directory("./src")
py_time = time.time() - start

print(f"Rust: {rust_time:.2f}s")
print(f"Python: {py_time:.2f}s")
print(f"Speedup: {py_time/rust_time:.1f}x")
```

## Troubleshooting

### Cargo not found

Ensure Rust is installed and in your PATH:
```bash
which cargo
```

### Python.h not found

Install Python development headers:
```bash
# Ubuntu/Debian
sudo apt-get install python3-dev

# macOS (with Homebrew)
brew install python
```

### maturin build fails

Try updating maturin:
```bash
pip install --upgrade maturin
```

## Optional: Cross-compilation

To build for different platforms:

```bash
# Install cross-compilation targets
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-apple-darwin

# Build for specific target
maturin build --release --target x86_64-unknown-linux-gnu
```

## Benchmarking

Run benchmarks to measure performance:

```bash
cd rust/knox-core
cargo bench
```

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Build Rust Module

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - run: pip install maturin
      - run: cd rust/knox-core && maturin build --release
```
