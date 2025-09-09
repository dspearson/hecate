#!/usr/bin/env bash
# Build script for musl static binary

# Use environment or system tools
export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"
export CXX_x86_64_unknown_linux_musl="${CXX_x86_64_unknown_linux_musl:-g++}"
export AR_x86_64_unknown_linux_musl="${AR_x86_64_unknown_linux_musl:-ar}"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:-gcc}"

# Check if we're in a Nix shell and need to escape it for musl builds
if [ -n "$IN_NIX_SHELL" ]; then
    echo "Detected Nix shell, escaping to system environment for musl build..."
    # Escape Nix shell completely by using env -i to clear environment
    # Keep only essential vars and our musl-specific ones
    exec env -i \
        HOME="$HOME" \
        USER="$USER" \
        PATH="/home/dsp/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
        CC_x86_64_unknown_linux_musl="gcc" \
        CXX_x86_64_unknown_linux_musl="g++" \
        AR_x86_64_unknown_linux_musl="ar" \
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="gcc" \
        bash -c 'cargo build --release --target x86_64-unknown-linux-musl "$@"' -- "$@"
else
    # Not in Nix shell, use cargo normally
    cargo build --release --target x86_64-unknown-linux-musl "$@"
fi