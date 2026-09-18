# verify.ps1 — Windows 本地完整验证（CI 同款命令）
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "==> cargo build --workspace"
cargo build --workspace
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> cargo test --workspace"
cargo test --workspace
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> guest acceptance (spec 9.4)"
cargo run -q -p vela-cli --bin vela -- run guest/hello
if ($LASTEXITCODE -ne 0) { exit 1 }
cargo run -q -p vela-cli --bin vela -- run guest/torture
if ($LASTEXITCODE -ne 0) { exit 1 }
cargo run -q -p vela-cli --bin vela -- run guest/tls
if ($LASTEXITCODE -ne 0) { exit 1 }
if (Test-Path guest/hello-musl) {
    cargo run -q -p vela-cli --bin vela -- run guest/hello-musl
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

Write-Host "==> all checks passed"
