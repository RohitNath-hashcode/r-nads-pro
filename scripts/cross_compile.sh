#!/bin/bash
# R-NADS Cross-Compilation Script for Linux/macOS
# Cross-compiles the R-NADS engine for Raspberry Pi (AArch64 Linux) using `cross` (Docker).

set -e

echo -e "\e[36m=== R-NADS Raspberry Pi Cross-Compiler ===\e[0m"

# 1. Check if Docker is running
echo -e "\e[33m[1/3] Checking Docker daemon status...\e[0m"
if ! docker info > /dev/null 2>&1; then
    echo -e "\e[31mError: Docker daemon is not running. Please start Docker and try again.\e[0m"
    exit 1
fi
echo -e "\e[32mDocker is running.\e[0m"

# 2. Check if cargo-cross is installed
echo -e "\e[33m[2/3] Checking if 'cross' tool is installed...\e[0m"
if ! command -v cross &> /dev/null; then
    echo -e "\e[36m'cross' is not installed. Installing via cargo...\e[0m"
    cargo install cross --git https://github.com/cross-rs/cross
fi
echo -e "\e[32m'cross' tool is ready.\e[0m"

# 3. Compile for target aarch64-unknown-linux-gnu
echo -e "\e[33m[3/3] Cross-compiling for aarch64-unknown-linux-gnu...\e[0m"
cross build --target aarch64-unknown-linux-gnu --release

echo -e "\n\e[32m=== Success! ===\e[0m"
echo -e "\e[32mBinary built at: target/aarch64-unknown-linux-gnu/release/r-nads-bin\e[0m"
