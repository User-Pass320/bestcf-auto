$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

$logDir = Join-Path $projectRoot "bestcf_work"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logPath = Join-Path $logDir "update-local-and-push.log"
Start-Transcript -Path $logPath -Append | Out-Null

trap {
    Write-Error $_
    try {
        Stop-Transcript | Out-Null
    } catch {
    }
    exit 1
}

function Assert-NativeCommandSucceeded {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName
    )

    if ($LASTEXITCODE -ne 0) {
        throw "$CommandName failed with exit code $LASTEXITCODE"
    }
}

$mihomo = "E:\v2rayN-windows-64\bin\mihomo\mihomo.exe"
if (-not (Test-Path -LiteralPath $mihomo)) {
    throw "mihomo not found: $mihomo"
}
if (-not (Test-Path -LiteralPath ".\template.yaml")) {
    throw "template.yaml not found. This private file is required for local testing."
}

New-Item -ItemType Directory -Force -Path ".\public" | Out-Null

python .\bestcf_tool.py `
    --profile balanced `
    --workdir .\bestcf_work `
    --template .\template.yaml `
    --mihomo $mihomo `
    --output .\public\bestcf_final.txt
Assert-NativeCommandSucceeded "bestcf_tool.py update"

python .\bestcf_tool.py validate-output .\public\bestcf_final.txt --min-lines 10 --min-regions 1
Assert-NativeCommandSucceeded "bestcf_tool.py validate-output"

$lineCount = (Get-Content -LiteralPath ".\public\bestcf_final.txt" | Measure-Object -Line).Lines

Copy-Item -LiteralPath ".\bestcf_work\bestcf_tested.csv" -Destination ".\public\bestcf_tested.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_failed.csv" -Destination ".\public\bestcf_failed.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_sources.csv" -Destination ".\public\bestcf_sources.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_other_regions.csv" -Destination ".\public\bestcf_other_regions.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_region_counts.csv" -Destination ".\public\bestcf_region_counts.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_geo_provider_stats.csv" -Destination ".\public\bestcf_geo_provider_stats.csv" -Force -ErrorAction SilentlyContinue

git add public/
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "No public result changes to commit."
    Stop-Transcript | Out-Null
    exit 0
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
git commit -m "Update BestCF results ($timestamp)"
Assert-NativeCommandSucceeded "git commit"
git push --porcelain
Assert-NativeCommandSucceeded "git push"

Write-Host "BestCF local update pushed. Lines: $lineCount"
Stop-Transcript | Out-Null
