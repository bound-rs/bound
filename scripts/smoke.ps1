# Smoke test of the release binaries on Windows, following the README
# examples. Uses the real bound.exe and the bound-launcher.exe next to it.
#
#   scripts/smoke.ps1 [-Bin DIR] [-Fixture PATH]
#
# -Bin defaults to target\release. -Fixture is the bound-fixture test
# program (built with `cargo build --release -p bound-tests --bin bound-fixture`);
# when given, the embedded-file example runs with it instead of a system tool.
param(
    [string]$Bin = "target\release",
    [string]$Fixture = ""
)
$ErrorActionPreference = "Stop"

$bound = Join-Path (Resolve-Path $Bin) "bound.exe"
if ($Fixture) { $Fixture = (Resolve-Path $Fixture).Path }
$work = Join-Path ([IO.Path]::GetTempPath()) ("bound smoke " + [Guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
Push-Location $work

function Fail($message) { throw "smoke: FAIL: $message" }
function Step($message) { Write-Host "smoke: $message" }
function Check-Exit($what) { if ($LASTEXITCODE -ne 0) { Fail "$what exited with $LASTEXITCODE" } }

try {
    Step "argument binding with a native tool"
    Set-Content -NoNewline -Path server.log -Value "ok`r`nERROR one`r`nfine`r`nERROR two`r`n"
    & $bound -o find-errors -- findstr.exe /N ERROR; Check-Exit "bound"
    if (-not (Test-Path find-errors.exe)) { Fail "find-errors.exe was not created (.exe is appended on Windows)" }
    $out = (& .\find-errors.exe server.log) -join "`n"
    if ($out -ne "2:ERROR one`n4:ERROR two") { Fail "unexpected output: $out" }

    Step "embedded file survives removal of the original"
    Set-Content -NoNewline -Path config.toml -Value "[db]`r`nurl = `"x`"`r`n"
    if ($Fixture) {
        & $bound -o show-config.exe -- $Fixture read "@file:config.toml"; Check-Exit "bound"
    } else {
        & $bound -o show-config.exe -- findstr.exe /R "^" "@file:config.toml"; Check-Exit "bound"
    }
    Remove-Item config.toml
    $out = (& .\show-config.exe) -join "`n"
    if ($out -ne "[db]`nurl = `"x`"") { Fail "unexpected output: $out" }

    Step "paths with spaces"
    New-Item -ItemType Directory "Program Files Test" | Out-Null
    Copy-Item (Join-Path $env:SystemRoot "System32\findstr.exe") "Program Files Test\find tool.exe"
    & $bound --embed-program -o spaced.exe -- ".\Program Files Test\find tool.exe" /N ERROR; Check-Exit "bound"
    Remove-Item -Recurse "Program Files Test"
    $out = (& .\spaced.exe server.log) -join "`n"
    if ($out -ne "2:ERROR one`n4:ERROR two") { Fail "unexpected output: $out" }

    Step "an artifact named like its program runs the next one in PATH"
    New-Item -ItemType Directory wrappers | Out-Null
    & $bound -q -o wrappers\findstr.exe -- findstr.exe /N ERROR; Check-Exit "bound"
    $saved = $env:Path
    try {
        $env:Path = (Join-Path $work "wrappers") + ";" + $saved
        $out = (& .\wrappers\findstr.exe server.log) -join "`n"
    } finally { $env:Path = $saved }
    if ($out -ne "2:ERROR one`n4:ERROR two") { Fail "unexpected output: $out" }

    Step "shared bundles"
    $env:BOUND_CACHE_DIR = Join-Path $work "cache"
    try {
        Set-Content -NoNewline -Path data.txt -Value "shared data"
        & $bound -q -o shared.exe --bundle shared --include data.txt --cwd bundle -- findstr.exe /R "^" data.txt; Check-Exit "bound"
        $first = (& .\shared.exe) -join "`n"; Check-Exit "shared.exe"
        $second = (& .\shared.exe) -join "`n"; Check-Exit "shared.exe"
        if ($first -ne "shared data" -or $second -ne $first) { Fail "unexpected output: $first / $second" }
        $list = (& $bound cache list) -join "`n"
        if ($list -notmatch "Shared bundles: 1") { Fail "cache list: $list" }
        $clean = (& $bound cache clean) -join "`n"
        if ($clean -notmatch "Removed 1 cache entry") { Fail "cache clean: $clean" }
    } finally { Remove-Item Env:BOUND_CACHE_DIR }

    Step "exit status"
    & $bound -o fail.exe -- cmd.exe /d /c "exit 42"; Check-Exit "bound"
    & .\fail.exe
    if ($LASTEXITCODE -ne 42) { Fail "expected exit status 42, got $LASTEXITCODE" }

    Step "inspect and verify"
    & $bound inspect .\show-config.exe; Check-Exit "inspect"
    $json = (& $bound inspect --json .\show-config.exe) | ConvertFrom-Json
    if ($json.inspect_format -ne 1 -or $json.platform.os -ne "windows") { Fail "inspect --json" }
    & $bound verify .\show-config.exe; Check-Exit "verify"

    Step "corruption is detected"
    # Damage the bundled data. (Not the end of the file: in a signed
    # artifact that is the signature, which bound leaves to signtool.)
    $offset = [int]$json.regions.payload.offset
    $bytes = [IO.File]::ReadAllBytes((Join-Path $work "show-config.exe"))
    $bytes[$offset] = $bytes[$offset] -bxor 0x20
    [IO.File]::WriteAllBytes((Join-Path $work "broken.exe"), $bytes)
    # Windows PowerShell 5.1 turns a native command's stderr into errors,
    # which "Stop" would make fatal: this command is expected to fail.
    $ErrorActionPreference = "Continue"
    & $bound verify .\broken.exe *> $null
    $code = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($code -eq 0) { Fail "corruption was not detected" }
    # That failure was expected; a caller that reports the last native
    # command's status (as CI's PowerShell does) must not see it.
    $global:LASTEXITCODE = 0

    Write-Host "smoke: all checks passed"
}
finally {
    Pop-Location
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
