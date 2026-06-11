$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

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

if (-not (Test-Path -LiteralPath ".\public\bestcf_final.txt")) {
    throw "public\bestcf_final.txt was not generated."
}

$lineCount = (Get-Content -LiteralPath ".\public\bestcf_final.txt" | Measure-Object -Line).Lines
if ($lineCount -lt 10) {
    throw "Generated bestcf_final.txt has too few lines: $lineCount"
}

Copy-Item -LiteralPath ".\bestcf_work\bestcf_tested.csv" -Destination ".\public\bestcf_tested.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_failed.csv" -Destination ".\public\bestcf_failed.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_sources.csv" -Destination ".\public\bestcf_sources.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_other_regions.csv" -Destination ".\public\bestcf_other_regions.csv" -Force -ErrorAction SilentlyContinue

git add public/
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "No public result changes to commit."
    exit 0
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
git commit -m "Update BestCF results ($timestamp)"
git push

Write-Host "BestCF local update pushed. Lines: $lineCount"
