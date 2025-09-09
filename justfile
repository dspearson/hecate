# Hecate build and development tasks
# Default target is glibc release build

# Default recipe (runs when you just type 'just')
default: help

# Build release binary (glibc, dynamically linked)
build:
    cargo build --release

# Build debug binary (glibc)
build-debug:
    cargo build

# Build static musl binary
build-musl:
    cargo build --release --target x86_64-unknown-linux-musl

# Run all tests
test:
    cargo test

# Run tests with output
test-verbose:
    cargo test -- --nocapture

# Run clippy linter
clippy:
    cargo clippy

# Run clippy with all targets
clippy-all:
    cargo clippy --all-targets --all-features

# Format code
fmt:
    cargo fmt

# Check formatting without making changes
fmt-check:
    cargo fmt -- --check

# Clean build artifacts
clean:
    cargo clean

# Deep clean including target directory
clean-all:
    cargo clean
    rm -rf target/

# Run security audit
audit:
    cargo audit

# Check for outdated dependencies
outdated:
    cargo outdated

# Update dependencies
update:
    cargo update

# Build and run with verbose output
run *ARGS:
    cargo run --release -- {{ARGS}}

# Build and run debug version
run-debug *ARGS:
    cargo run -- {{ARGS}}

# Full check: fmt, clippy, test, build
check: fmt clippy test build
    @echo "✓ All checks passed!"

# Check musl build
check-musl: build-musl
    @echo "✓ Musl build successful!"
    @file target/x86_64-unknown-linux-musl/release/hecate | grep -q "statically linked" && echo "✓ Binary is statically linked" || echo "✗ Binary is not statically linked"

# Show binary sizes
sizes:
    @echo "Binary sizes:"
    @ls -lh target/x86_64-unknown-linux-gnu/release/hecate 2>/dev/null && echo "  glibc: $(ls -lh target/x86_64-unknown-linux-gnu/release/hecate 2>/dev/null | awk '{print $5}')" || echo "  glibc: not built"
    @ls -lh target/x86_64-unknown-linux-musl/release/hecate 2>/dev/null && echo "  musl:  $(ls -lh target/x86_64-unknown-linux-musl/release/hecate 2>/dev/null | awk '{print $5}')" || echo "  musl:  not built"

# Install locally (to ~/.cargo/bin)
install:
    cargo install --path .

# Uninstall
uninstall:
    cargo uninstall hecate

# Generate documentation
doc:
    cargo doc --no-deps --open

# Generate documentation for all dependencies
doc-all:
    cargo doc --open

# Run benchmarks (if any)
bench:
    cargo bench

# Count lines of code
loc:
    @echo "Lines of code:"
    @find src -name "*.rs" | xargs wc -l | tail -1

# Show help
help:
    @just --list