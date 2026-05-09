# SIFR v0.3 fail-closed reproduction script (PowerShell variant of reproduce_all.sh).
$ErrorActionPreference = "Stop"

$Repo = Split-Path -Parent $PSScriptRoot
Set-Location $Repo

function Step($msg)  { Write-Host ""; Write-Host "=== $msg ===" -ForegroundColor Cyan }
function Ok($msg)    { Write-Host ("ok    " + $msg) -ForegroundColor Green }
function FailOut($msg) { Write-Host ("FAIL: " + $msg) -ForegroundColor Red; exit 1 }

Step "1/9 Verify environment"
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { FailOut "python not on PATH" }
$pyv = & python -c "import sys; print('.'.join(map(str, sys.version_info[:2])))"
Ok "Python $pyv"

$java = (Get-Command java -ErrorAction SilentlyContinue).Source
if (-not $java) {
    $java = "C:\Users\USER\AppData\Local\Programs\Microsoft\jdk-17.0.10.7-hotspot\bin\java.exe"
}
if (-not (Test-Path $java)) { FailOut "java not found (install JRE 11+; needed for TLC)" }
Ok "java available: $java"

if (-not $env:TLA_TOOLS_PATH) { $env:TLA_TOOLS_PATH = "$Repo\formal\tools\tla2tools.jar" }
if (-not (Test-Path $env:TLA_TOOLS_PATH)) { FailOut "tla2tools.jar missing at $($env:TLA_TOOLS_PATH); run scripts/install_tla.ps1" }
Ok "tla2tools.jar present"

& python -c "import aioquic, wasmtime, argon2, httpx, cryptography, numpy, pytest, matplotlib" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { FailOut "missing required Python deps; run: pip install -e .[dev]" }
Ok "Python deps importable"

Step "2/9 Install dev dependencies"
& python -m pip install -q -e ".[dev]"
if ($LASTEXITCODE -ne 0) { FailOut "pip install failed" }
Ok "deps installed"

Step "3/9 Run pytest (with SIFR_TLC_FROZEN=1)"
$env:SIFR_TLC_FROZEN = "1"
& python -m pytest -q
if ($LASTEXITCODE -ne 0) { FailOut "pytest failed" }
Ok "all tests passed"

Step "4/9 Run demos"
$demos = @(
    "examples\demo_secure_quic_wasm_did_flow.py",
    "examples\demo_adversary_cases.py",
    "examples\demo_v0_3_adversary_cases.py",
    "examples\demo_wasm_calculator.py",
    "examples\demo_did_resolution.py",
    "examples\demo_key_rotation.py",
    "examples\demo_capability_credential.py",
    "examples\demo_revoked_capability.py",
    "examples\demo_replay_rejection.py"
)
foreach ($d in $demos) {
    if (-not (Test-Path $d)) { FailOut "missing demo: $d" }
    & python $d *> $null
    if ($LASTEXITCODE -ne 0) { FailOut "demo failed: $d" }
    Ok ("demo: " + $d)
}

Step "5/9 Run all benchmarks (v0.3)"
$env:SIFR_BENCH_VERSION = "v0.3"
& bash scripts\run_all_benchmarks.sh
if ($LASTEXITCODE -ne 0) { FailOut "benchmark suite failed (bash required for shell loop)" }
Ok "benchmarks regenerated"

Step "6/9 Regenerate figures"
& python scripts\generate_all_figures.py
if ($LASTEXITCODE -ne 0) { FailOut "figure regeneration failed" }
Ok "figures regenerated"

Step "7b. Symbolic protocol model"
$tamarin = (Get-Command tamarin-prover -ErrorAction SilentlyContinue).Source
$proverif = (Get-Command proverif -ErrorAction SilentlyContinue).Source
if ($tamarin) {
    Write-Host "running Tamarin against formal/tamarin/sifr_core.spthy ..."
    & $tamarin --prove formal/tamarin/sifr_core.spthy > formal/output/tamarin_output.txt 2>&1
    if ($LASTEXITCODE -eq 0) { Ok "Tamarin: lemmas proven" } else { Write-Host "FAIL: Tamarin lemma did not prove." -ForegroundColor Red }
} elseif ($proverif -and (Test-Path "formal/proverif/sifr_core.pv")) {
    & $proverif "formal/proverif/sifr_core.pv" > formal/output/proverif_output.txt 2>&1
} else {
    Write-Host "INFO: symbolic proof tool missing"
    Write-Host "      Install Tamarin (https://tamarin-prover.com/) or ProVerif"
    Write-Host "      to verify formal/tamarin/sifr_core.spthy."
    Write-Host "      v0.4 quality gate item 'symbolic model run' will read NO."
}

Step "7/9 Run TLC against v0.3 model"
New-Item -Force -ItemType Directory -Path formal\output | Out-Null
& $java -XX:+UseParallelGC -cp $env:TLA_TOOLS_PATH tlc2.TLC `
    -workers auto -deadlock -config formal\MC.cfg formal\sifr_capability.tla `
    > formal\output\tlc_output.txt 2>&1
if ($LASTEXITCODE -ne 0) { FailOut "TLC reported violations -- see formal/output/tlc_output.txt" }
Select-String -Path formal\output\tlc_output.txt -Pattern "No error has been found" -Quiet
if (-not $?) { FailOut "TLC output missing success marker" }
& python scripts\refresh_formal_metadata.py
if ($LASTEXITCODE -ne 0) { FailOut "could not refresh formal metadata" }
Ok "TLC verified, metadata refreshed"

Step "8/9 Verify required artifacts"
$required = @(
    "benchmarks\results\v0.3\adversary_rejection.json",
    "benchmarks\results\v0.3\did_resolution.csv",
    "benchmarks\results\v0.3\wasm_overhead.csv",
    "benchmarks\results\v0.3\quic_latency.csv",
    "benchmarks\results\v0.3\replay_overhead.csv",
    "benchmarks\results\v0.3\revocation_overhead.csv",
    "benchmarks\results\v0.3\credential_verification.csv",
    "benchmarks\results\v0.3\manifest.json",
    "paper\figures\figure_manifest.json",
    "paper\figures\benchmark_v0_3_adversary.png",
    "formal\output\tlc_output.txt",
    "formal\output\tlc_metadata.json",
    "formal\output\model_hashes.json",
    "docs\proof_obligations_v0_3.md",
    "review\v0_3_strict_quality_gate.md"
)
foreach ($f in $required) {
    if (-not (Test-Path $f)) { FailOut "required artifact missing: $f" }
}
Ok "all required artifacts present"

Step "9/9 Proof summary"
$commit = (& git rev-parse --short HEAD 2>$null)
if (-not $commit) { $commit = "no-git" }
$dirty = ""
& git diff --quiet 2>$null
if ($LASTEXITCODE -ne 0) { $dirty = " (dirty)" }

Write-Host ""
Write-Host "SIFR v0.3 reproduction summary"
Write-Host "  commit:     $commit$dirty"
Write-Host "  python:     $pyv"
Write-Host "  benchmarks: benchmarks\results\v0.3\"
Write-Host "  figures:    paper\figures\"
Write-Host "  formal:     formal\output\tlc_output.txt"
Write-Host "  proof:      docs\proof_obligations_v0_3.md"
Write-Host "  gate:       review\v0_3_strict_quality_gate.md"
