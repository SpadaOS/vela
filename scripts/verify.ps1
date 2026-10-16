# Exercise an exact binary, including an extracted release package.
param(
    [string]$Executable,
    [string]$GuestDirectory = (Join-Path $PSScriptRoot '../guest/bin'),
    [string]$Report = (Join-Path $PSScriptRoot '../release/validation'),
    [switch]$RequireBusybox, [switch]$RequireThreads,
    [switch]$RequireNetwork, [switch]$RequireSignals
)
$ErrorActionPreference = 'Stop'
if (-not $Executable) {
    Push-Location (Join-Path $PSScriptRoot '..')
    try {
        cargo build --workspace
        if ($LASTEXITCODE) { throw 'cargo build failed' }
        $Executable = Join-Path $pwd 'target/debug/vela.exe'
    } finally { Pop-Location }
}
$acceptanceArgs = @((Join-Path $PSScriptRoot 'acceptance.py'), '--exe', $Executable,
    '--guests', $GuestDirectory, '--report', $Report)
if ($RequireBusybox) { $acceptanceArgs += '--busybox' }
if ($RequireThreads) { $acceptanceArgs += '--threads' }
if ($RequireSignals) { $acceptanceArgs += '--signals' }
if ($RequireNetwork) { $acceptanceArgs += '--network' }
python @acceptanceArgs
if ($LASTEXITCODE) { throw "acceptance failed; see $Report" }
