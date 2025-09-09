# Hecate build and development tasks
# Monorepo with client and server components

# Default recipe (runs when you just type 'just')
default: help

# Build all components
build: build-client build-server

# Build client release binary (glibc, dynamically linked)
build-client:
    cd client && cargo build --release

# Build server release binary
build-server:
    cd server && cargo build --release

# Build all debug binaries
build-debug: build-client-debug build-server-debug

# Build client debug binary
build-client-debug:
    cd client && cargo build

# Build server debug binary
build-server-debug:
    cd server && cargo build

# Build static musl binary for client
build-musl:
    cd client && cargo build --release --target x86_64-unknown-linux-musl

# Run all tests
test: test-client test-server

# Run client tests
test-client:
    cd client && cargo test

# Run server tests
test-server:
    cd server && cargo test

# Run tests with output
test-verbose:
    cd client && cargo test -- --nocapture
    cd server && cargo test -- --nocapture

# Run clippy linter
clippy:
    cd client && cargo clippy
    cd server && cargo clippy

# Run clippy with all targets
clippy-all:
    cd client && cargo clippy --all-targets --all-features
    cd server && cargo clippy --all-targets --all-features

# Format code
fmt:
    cd client && cargo fmt
    cd server && cargo fmt

# Check formatting without making changes
fmt-check:
    cd client && cargo fmt -- --check
    cd server && cargo fmt -- --check

# Clean build artifacts
clean:
    cd client && cargo clean
    cd server && cargo clean

# Deep clean including target directory
clean-all:
    cd client && cargo clean
    cd server && cargo clean
    rm -rf client/target/ server/target/

# Run security audit
audit:
    cd client && cargo audit
    cd server && cargo audit

# Check for outdated dependencies
outdated:
    cd client && cargo outdated
    cd server && cargo outdated

# Update dependencies
update:
    cd client && cargo update
    cd server && cargo update

# Run client with verbose output
run-client *ARGS:
    cd client && cargo run --release -- {{ARGS}}

# Run server
run-server *ARGS:
    cd server && cargo run --release -- {{ARGS}}

# Run client debug version
run-client-debug *ARGS:
    cd client && cargo run -- {{ARGS}}

# Run server debug version
run-server-debug *ARGS:
    cd server && cargo run -- {{ARGS}}

# Full check: fmt, clippy, test, build
check: fmt clippy test build
    @echo "✓ All checks passed!"

# Check musl build
check-musl: build-musl
    @echo "✓ Musl build successful!"
    @file client/target/x86_64-unknown-linux-musl/release/hecate | grep -q "statically linked" && echo "✓ Binary is statically linked" || echo "✗ Binary is not statically linked"

# Show binary sizes
sizes:
    @echo "Binary sizes:"
    @ls -lh client/target/release/hecate 2>/dev/null && echo "  client (glibc): $(ls -lh client/target/release/hecate 2>/dev/null | awk '{print $5}')" || echo "  client (glibc): not built"
    @ls -lh client/target/x86_64-unknown-linux-musl/release/hecate 2>/dev/null && echo "  client (musl):  $(ls -lh client/target/x86_64-unknown-linux-musl/release/hecate 2>/dev/null | awk '{print $5}')" || echo "  client (musl):  not built"
    @ls -lh server/target/release/mercury 2>/dev/null && echo "  server:         $(ls -lh server/target/release/mercury 2>/dev/null | awk '{print $5}')" || echo "  server:         not built"

# Install locally (to ~/.cargo/bin)
install: install-client install-server

# Install client
install-client:
    cd client && cargo install --path .

# Install server
install-server:
    cd server && cargo install --path .

# Uninstall
uninstall:
    cargo uninstall hecate
    cargo uninstall mercury

# Generate documentation
doc:
    cd client && cargo doc --no-deps --open

# Generate documentation for all dependencies
doc-all:
    cd client && cargo doc --open

# Run benchmarks (if any)
bench:
    cd client && cargo bench
    cd server && cargo bench

# Count lines of code
loc:
    @echo "Lines of code:"
    @echo "Client:" && find client/src -name "*.rs" | xargs wc -l | tail -1
    @echo "Server:" && find server/src -name "*.rs" | xargs wc -l | tail -1

# Show help
help:
    @just --list