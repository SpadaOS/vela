#!/usr/bin/env bash
# verify.sh — Linux/macOS 逻辑验证（guest 真实执行仅 Windows 支持）
set -e
cd "$(dirname "$0")/.."

echo "==> cargo build --workspace"
cargo build --workspace

echo "==> cargo test --workspace"
cargo test --workspace

echo "==> all checks passed (guest execution requires Windows)"
