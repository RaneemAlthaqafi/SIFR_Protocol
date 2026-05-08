# Wrapper that runs TLC against sifr_capability.tla using MC.cfg.
#
# Prerequisites:
#   - Java JRE 11+ in PATH
#   - tla2tools.jar at $env:TLA_TOOLS_PATH
#     (or pass -ToolsPath C:\path\to\tla2tools.jar)
#
# Usage:
#   pwsh formal/run_tlc.ps1
#
# Output:
#   formal/output/tlc_output.txt -- captured TLC stdout/stderr
#   exit code 0 on "No error has been found", non-zero on any violation.

param(
    [string]$ToolsPath = $env:TLA_TOOLS_PATH
)

if (-not $ToolsPath -or -not (Test-Path $ToolsPath)) {
    Write-Error "tla2tools.jar not found. Set TLA_TOOLS_PATH or pass -ToolsPath. See scripts/install_tla.ps1 to download."
    exit 2
}

$here = $PSScriptRoot
$out_dir = Join-Path $here "output"
New-Item -ItemType Directory -Force -Path $out_dir | Out-Null
$out_file = Join-Path $out_dir "tlc_output.txt"

Push-Location $here
try {
    & java -XX:+UseParallelGC -cp $ToolsPath tlc2.TLC -workers auto -deadlock -config MC.cfg sifr_capability.tla 2>&1 | Tee-Object -FilePath $out_file
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Write-Host "OK -- output at $out_file"
    } else {
        Write-Host "TLC exited with code $code -- see $out_file"
    }
    exit $code
}
finally {
    Pop-Location
}
