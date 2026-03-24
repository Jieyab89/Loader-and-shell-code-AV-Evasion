#!/bin/bash

# Author Jieyab89 
# Usage chmod +x IronPE-loader-Linux-Compile.sh

set -e

# ===== COLOR SETUP =====
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_ok() {
    echo -e "${GREEN}[+] $1${NC}"
}

log_err() {
    echo -e "${RED}[-] $1${NC}"
}

trap 'log_err "Script failed at line $LINENO"; exit 1' ERR

# ===== START =====

log_ok "Update package list..."
sudo apt update

log_ok "Install compiler mingw 64..."
sudo apt install -y mingw-w64

log_ok "Install rustup..."
sudo apt install -y rustup

log_ok "Set Rust stable as default..."
rustup default stable

log_ok "Add Windows target (x86_64-pc-windows-gnu)..."
rustup target add x86_64-pc-windows-gnu

log_ok "Build project for Windows (release)..."
cargo build --release --target x86_64-pc-windows-gnu

log_ok "Build finished!"

log_ok "Output binary located at:"
echo -e "${GREEN}target/x86_64-pc-windows-gnu/release/${NC}"

log_ok "CC and Loader made by : ISSAC (iss4cf0ng)"