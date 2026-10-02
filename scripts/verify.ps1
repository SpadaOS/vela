# verify.ps1 — Windows 本地完整验证（CI 同款命令）
param([switch]$RequireBusybox, [switch]$RequireThreads)
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

    $busyRoot = Join-Path ([System.IO.Path]::GetTempPath()) "vela-busybox-root-$PID"
    New-Item -ItemType Directory -Force -Path (Join-Path $busyRoot "data") | Out-Null
    Set-Content -LiteralPath (Join-Path $busyRoot "data/input.txt") -Value "needle`nother`n" -NoNewline
    try {
        cargo run -q -p vela-cli --bin vela -- run --soft-tls --root $busyRoot guest/bin/busybox grep needle /data/input.txt
        if ($LASTEXITCODE -ne 0) { throw "BusyBox grep root acceptance failed" }
        cargo run -q -p vela-cli --bin vela -- run --soft-tls --root $busyRoot guest/bin/busybox find /data -name input.txt
        if ($LASTEXITCODE -ne 0) { throw "BusyBox find root acceptance failed" }
        cargo run -q -p vela-cli --bin vela -- run --soft-tls --root $busyRoot guest/bin/busybox tar -cf /data/archive.tar /data/input.txt
        if ($LASTEXITCODE -ne 0) { throw "BusyBox tar root acceptance failed" }
        # BusyBox refuses binary output to a terminal unless -f explicitly forces it.
        cargo run -q -p vela-cli --bin vela -- run --soft-tls --root $busyRoot guest/bin/busybox gzip -f -c /data/input.txt
        if ($LASTEXITCODE -ne 0) { throw "BusyBox gzip root acceptance failed" }
    } finally {
        Remove-Item -LiteralPath $busyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
if ($RequireThreads) {
    Write-Host "==> pthread acceptance"
    if (-not (Test-Path guest/bin/pthread-test)) { throw "guest/bin/pthread-test is required" }
    1..3 | ForEach-Object {
        cargo run -q -p vela-cli --bin vela -- run --soft-tls guest/bin/pthread-test
        if ($LASTEXITCODE -ne 0) { throw "pthread guest failed on iteration $_" }
    }
}

Write-Host "==> all checks passed"
