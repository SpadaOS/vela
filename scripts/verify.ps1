# verify.ps1 — Windows 本地完整验证（CI 同款命令）
param([switch]$RequireBusybox)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "==> cargo build --workspace"
cargo build --workspace
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> cargo test --workspace"
cargo test --workspace
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> guest acceptance (spec 9.4)"
cargo run -q -p vela-cli --bin vela -- run guest/bin/hello
if ($LASTEXITCODE -ne 0) { exit 1 }
cargo run -q -p vela-cli --bin vela -- run guest/bin/torture
if ($LASTEXITCODE -ne 0) { exit 1 }
cargo run -q -p vela-cli --bin vela -- run --soft-tls guest/bin/tls
if ($LASTEXITCODE -ne 0) { exit 1 }
if (Test-Path guest/bin/hello-musl) {
    cargo run -q -p vela-cli --bin vela -- run --soft-tls guest/bin/hello-musl
    if ($LASTEXITCODE -ne 0) { exit 1 }
}
if ($RequireBusybox) {
    Write-Host "==> BusyBox acceptance"
    if (-not (Test-Path guest/bin/busybox)) { throw "guest/bin/busybox is required" }
    cargo run -q -p vela-cli --bin vela -- run --soft-tls guest/bin/busybox echo verify-busybox
    if ($LASTEXITCODE -ne 0) { exit 1 }
    cargo run -q -p vela-cli --bin vela -- run --soft-tls guest/bin/busybox true
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

Write-Host "==> all checks passed"
