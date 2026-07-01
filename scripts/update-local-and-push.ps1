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

function Stop-BestCFWorkerProcesses {
    $patterns = @(
        "bestcf_work",
        "bestcf-auto"
    )
    $processes = Get-CimInstance Win32_Process |
        Where-Object {
            $commandLine = $_.CommandLine
            $_.Name -eq "mihomo.exe" -and
            $null -ne $commandLine -and
            ($patterns | Where-Object { $commandLine -like "*$_*" })
        }

    foreach ($process in $processes) {
        Write-Host "Stopping stale BestCF mihomo worker: pid=$($process.ProcessId) command=$($process.CommandLine)"
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }

    if ($processes) {
        Start-Sleep -Seconds 2
    }
}

$mihomo = "C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\bin\mihomo-windows-amd64-compatible.exe"
if (-not (Test-Path -LiteralPath $mihomo)) {
    $fallbackMihomo = "E:\v2rayN-windows-64\bin\mihomo\mihomo.exe"
    if (-not (Test-Path -LiteralPath $fallbackMihomo)) {
        $fallbackMihomo = Get-ChildItem -LiteralPath "C:\Users\sundewang\edgetunnel-bestcf-selfdeploy\bin" -Recurse -Filter "mihomo*.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    }
    if ($fallbackMihomo -and (Test-Path -LiteralPath $fallbackMihomo)) {
        $mihomo = $fallbackMihomo
        Write-Host "Using fallback mihomo: $mihomo"
    } else {
        throw "mihomo not found: $mihomo; fallback not found: E:\v2rayN-windows-64\bin\mihomo\mihomo.exe"
    }
}
if (-not (Test-Path -LiteralPath ".\template.yaml")) {
    throw "template.yaml not found. This private file is required for local testing."
}

New-Item -ItemType Directory -Force -Path ".\public" | Out-Null

Stop-BestCFWorkerProcesses

python .\bestcf_tool.py `
    --profile balanced `
    --workdir .\bestcf_work `
    --template .\template.yaml `
    --mihomo $mihomo `
    --output .\public\bestcf_final.txt `
    --no-geo-cache `
    --no-geo-hint-cache `
    --geo-providers ping0,ipwhois,ip_api `
    --geo-concurrency 16 `
    --selection-mode all-regions `
    --country-max 35 `
    --max-final-candidates 0 `
    --hk-suppression `
    --hk-suppress-strategy worker `
    --hk-probe-cap 105 `
    --hk-suppress-bucket-scope prefix `
    --hk-suppress-ipv4-prefix 20 `
    --hk-suppress-ipv6-prefix 40 `
    --hk-suppress-min-samples 6 `
    --hk-suppress-confidence 0.98 `
    --hk-suppress-explore-rate 0.05
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
