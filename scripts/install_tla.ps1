# Downloads tla2tools.jar to formal/tools/ for local TLC runs.
#
# This script does NOT install Java. Install JRE 11+ first:
#   winget install Microsoft.OpenJDK.17

$here = Split-Path -Parent $PSCommandPath
$repo = Resolve-Path (Join-Path $here "..")
$tools = Join-Path $repo "formal/tools"
$jar = Join-Path $tools "tla2tools.jar"
$url = "https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"

New-Item -ItemType Directory -Force -Path $tools | Out-Null
if (Test-Path $jar) {
    Write-Host "tla2tools.jar already at $jar"
} else {
    Write-Host "Downloading tla2tools.jar from $url"
    Invoke-WebRequest -Uri $url -OutFile $jar
}
$env:TLA_TOOLS_PATH = $jar
Write-Host "TLA_TOOLS_PATH set to $jar (this session only)."
Write-Host "To persist: [Environment]::SetEnvironmentVariable('TLA_TOOLS_PATH', '$jar', 'User')"
