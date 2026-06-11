$ErrorActionPreference = "Stop"

$repoUrl = "https://github.com/User-Pass320/bestcf-auto.git"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

$remote = git remote get-url origin 2>$null
if ($LASTEXITCODE -ne 0) {
    git remote add origin $repoUrl
} elseif ($remote -ne $repoUrl) {
    git remote set-url origin $repoUrl
}

git status --short
git push -u origin main
