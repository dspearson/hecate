#!/usr/bin/env bash
# Build script for standard glibc binary

cargo build --release --target x86_64-unknown-linux-gnu "$@"