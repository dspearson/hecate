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
    #!/usr/bin/env bash
    set -euo pipefail
    # Set environment variables for musl compilation
    export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"
    export CXX_x86_64_unknown_linux_musl="${CXX_x86_64_unknown_linux_musl:-g++}"
    export AR_x86_64_unknown_linux_musl="${AR_x86_64_unknown_linux_musl:-ar}"
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:-gcc}"
    
    # Check if we're in a Nix shell and need to escape it for musl builds
    if [ -n "${IN_NIX_SHELL:-}" ]; then
        echo "Detected Nix shell, escaping to system environment for musl build..."
        # Escape Nix shell completely by using env -i to clear environment
        exec env -i \
            HOME="$HOME" \
            USER="$USER" \
            PATH="/home/dsp/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
            CC_x86_64_unknown_linux_musl="gcc" \
            CXX_x86_64_unknown_linux_musl="g++" \
            AR_x86_64_unknown_linux_musl="ar" \
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="gcc" \
            bash -c 'cargo build --release --target x86_64-unknown-linux-musl'
    else
        cargo build --release --target x86_64-unknown-linux-musl
    fi

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