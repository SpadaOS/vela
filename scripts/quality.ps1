# The same mandatory gates run locally, on PR/main/manual CI, and on release.
param([string]$Zig = 'zig', [switch]$BuildBusybox, [string]$Bash = 'bash', [switch]$Package)
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
New-Item -ItemType Directory -Force release | Out-Null
Start-Transcript -Path release/quality.log -Force | Out-Null
try {
    foreach ($cargoArgs in @(
        @('fmt', '--all', '--', '--check'),
        @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings'),
        @('test', '--workspace'),
        @('build', '--workspace', '--release')
    )) {
        cargo @cargoArgs
        if ($LASTEXITCODE) { throw "cargo $cargoArgs failed" }
    }
    & "$PSScriptRoot/build-guests.ps1" -Zig $Zig
    if ($BuildBusybox) {
        $zigDirectory = Split-Path (Get-Command $Zig).Source
        $env:PATH = "$zigDirectory;$env:PATH"
        & $Bash tools/build-busybox.sh
        if ($LASTEXITCODE) { throw 'BusyBox build failed' }
    }
    & "$PSScriptRoot/verify.ps1" -Executable (Join-Path $pwd 'target/release/vela.exe') `
        -RequireBusybox -RequireThreads -RequireSignals -RequireNetwork
    if ($Package) {
        $packageArgs = @("$PSScriptRoot/package.py")
        if ($env:VELA_RELEASE_TAG) { $packageArgs += @('--tag', $env:VELA_RELEASE_TAG) }
        python @packageArgs
        if ($LASTEXITCODE) { throw 'package validation failed' }
    }
} finally { Stop-Transcript | Out-Null; Pop-Location }
