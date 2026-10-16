param([string]$Zig = 'zig', [string]$Profile = 'release')
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $version = & $Zig version
    if ($LASTEXITCODE -or $version.Trim() -ne '0.13.0') { throw "Zig 0.13.0 required; got $version" }
    & "target/$Profile/vela-mkhello.exe" guest/bin/hello
    if ($LASTEXITCODE) { throw 'mkhello failed' }
    foreach ($name in @('torture', 'tls', 'bench')) {
        & "target/$Profile/vela-mkguest.exe" $name "guest/bin/$name"
        if ($LASTEXITCODE) { throw "mkguest $name failed" }
    }
    $threaded = @('pthread-test', 'network-concurrency-test', 'signal-wait-test', 'epoll-test', 'signal-lifecycle-test')
    $sources = @('hello-musl', 'file-io', 'fs-exec', 'fork-test', 'pipe-a', 'pipe-b',
        'pthread-test', 'signal-test', 'socket-test', 'network-concurrency-test',
        'epoll-test', 'signal-wait-test', 'socket-edge-test', 'signal-lifecycle-test')
    foreach ($name in $sources) {
        $compilerArgs = @('cc', '-target', 'x86_64-linux-musl', '-fPIE', '-pie', '-O2')
        if ($name -in $threaded) { $compilerArgs += '-pthread' }
        & $Zig @compilerArgs -o "guest/bin/$name" "guest/src/$name.c"
        if ($LASTEXITCODE) { throw "guest build failed: $name" }
    }
    # Preserve the genuine dynamic executable/loader pair. Zig 0.13's bundled
    # musl build produces static PIE even with -dynamic; that is not this test.
    python "$PSScriptRoot/acceptance.py" --guests guest/bin --check-fixtures
    if ($LASTEXITCODE) { throw 'dynamic musl fixture validation failed' }
    & $Zig cc -target x86_64-linux-musl -nostdlib -fPIE -pie -o guest/bin/island-test guest/src/island-test.S
    if ($LASTEXITCODE) { throw 'island guest build failed' }
} finally { Pop-Location }
