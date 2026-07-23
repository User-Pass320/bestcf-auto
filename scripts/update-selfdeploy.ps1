[CmdletBinding()]
param(
    [ValidateSet('Prebuild', 'Wednesday', 'Sunday', 'Shadow', 'Manual')]
    [string]$RunMode = 'Manual',
    [ValidateSet('', 'Wednesday', 'Sunday')]
    [string]$EffectiveMode = '',
    [ValidateRange(1, 65535)]
    [int]$ExpectedInterfaceIndex = 19,
    [switch]$SkipSourceSync,
    [switch]$SkipCfst,
    [switch]$SkipDeploy,
    [switch]$SkipDependencyInstall
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$projectRoot = Split-Path -Parent $repo
Set-Location -LiteralPath $repo

function Assert-NativeCommandSucceeded([string]$Stage) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Stage failed with exit code $LASTEXITCODE"
    }
}

if (-not $SkipDependencyInstall) {
    python -m pip install -r (Join-Path $repo 'requirements.txt')
    Assert-NativeCommandSucceeded 'pip install'
}

$mode = $RunMode.ToLowerInvariant()
$effective = if ($EffectiveMode) { $EffectiveMode.ToLowerInvariant() } else { '' }
$work = Join-Path $repo 'bestcf_work'
$db = Join-Path $work 'bestcf_observations.sqlite'
$statefulWork = Join-Path $work 'stateful'
$staging = Join-Path $work 'staging'
$artifact = Join-Path $staging 'bestcf_final.txt'
$manifest = Join-Path $staging 'publish_manifest.json'
$summary = Join-Path $work 'stateful_run_summary.json'
$preflight = Join-Path $work 'direct_preflight_stateful.json'
$mihomo = Join-Path $projectRoot 'bin\mihomo-windows-amd64-compatible.exe'
$cfstDir = Join-Path $repo 'tools\cfst'
$cfstExe = Join-Path $cfstDir 'cfst.exe'
$cfstIpFile = Join-Path $cfstDir 'ip.txt'
$fallbackCfstDir = 'C:\Users\sundewang\bestcf-auto\tools\cfst'

New-Item -ItemType Directory -Force -Path $work, $statefulWork, $staging | Out-Null
if (-not (Test-Path -LiteralPath $mihomo)) {
    throw "mihomo executable is missing: $mihomo"
}

python (Join-Path $repo 'scripts\assert-cn-direct.py') `
    --expected-interface-index $ExpectedInterfaceIndex `
    --expected-loc CN `
    --output-json $preflight
Assert-NativeCommandSucceeded 'CN direct preflight'

if (-not (Test-Path -LiteralPath $db)) {
    if ($mode -ne 'prebuild') {
        throw "State database is missing; run -RunMode Prebuild first: $db"
    }
    python (Join-Path $repo 'scripts\migrate-pool-to-sqlite.py') `
        --workdir $work `
        --public-dir (Join-Path $repo 'public') `
        --template (Join-Path $repo 'template.yaml')
    Assert-NativeCommandSucceeded 'legacy asset migration'
}

$cfstRequired = (($mode -in @('sunday', 'manual')) -or ($mode -eq 'shadow' -and $effective -eq 'sunday')) -and (-not $SkipCfst)
if ($cfstRequired -and ((-not (Test-Path -LiteralPath $cfstExe)) -or (-not (Test-Path -LiteralPath $cfstIpFile)))) {
    $fallbackExe = Join-Path $fallbackCfstDir 'cfst.exe'
    $fallbackIp = Join-Path $fallbackCfstDir 'ip.txt'
    if ((-not (Test-Path -LiteralPath $fallbackExe)) -or (-not (Test-Path -LiteralPath $fallbackIp))) {
        throw "CFST executable or IP file is missing: $cfstDir"
    }
    New-Item -ItemType Directory -Force -Path $cfstDir | Out-Null
    Copy-Item -LiteralPath $fallbackExe -Destination $cfstExe -Force
    Copy-Item -LiteralPath $fallbackIp -Destination $cfstIpFile -Force
}

$statefulArgs = @(
    (Join-Path $repo 'scripts\stateful-update.py'),
    '--mode', $mode,
    '--db', $db,
    '--workdir', $statefulWork,
    '--template', (Join-Path $repo 'template.yaml'),
    '--mihomo', $mihomo,
    '--preflight-report', $preflight,
    '--output', $artifact,
    '--summary-json', $summary,
    '--publish-manifest', $manifest,
    '--cfst-exe', $cfstExe,
    '--cfst-ip-file', $cfstIpFile,
    '--soft-limit', '600',
    '--hard-limit', '800',
    '--hk-archive-sample', '100',
    '--country-max', '30',
    '--country-max-overrides', 'HK:20,DE:20',
    '--exit-ip-max', '3',
    '--min-lines', '10',
    '--min-regions', '3'
)
if ($effective) {
    $statefulArgs += @('--effective-mode', $effective)
}
if ($SkipSourceSync) {
    $statefulArgs += '--skip-source-sync'
}
if ($SkipCfst) {
    $statefulArgs += '--skip-cfst'
}

& python @statefulArgs
Assert-NativeCommandSucceeded "stateful $RunMode run"

if ($mode -in @('prebuild', 'shadow')) {
    Write-Host "Observation run completed without publication: $RunMode"
    exit 0
}
if ($SkipDeploy) {
    Write-Host "Staged artifact created without deployment: $artifact"
    exit 0
}

$summaryData = Get-Content -LiteralPath $summary -Raw | ConvertFrom-Json
$runId = [int]$summaryData.run_id
$expectedSha = ([string]$summaryData.artifact_sha256).ToUpperInvariant()
if ($runId -le 0 -or -not $expectedSha) {
    throw 'Stateful summary has no staged run ID or artifact SHA-256'
}
$actualSha = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToUpperInvariant()
if ($actualSha -ne $expectedSha) {
    throw "Local staged SHA-256 mismatch: expected=$expectedSha actual=$actualSha"
}

$pagesDir = Join-Path $staging "pages_$runId"
New-Item -ItemType Directory -Force -Path $pagesDir | Out-Null
Copy-Item -Path (Join-Path $repo 'public\*') -Destination $pagesDir -Recurse -Force
Copy-Item -LiteralPath $artifact -Destination (Join-Path $pagesDir 'bestcf_final.txt') -Force
Copy-Item -LiteralPath $summary -Destination (Join-Path $pagesDir 'stateful_run_summary.json') -Force
Copy-Item -LiteralPath $manifest -Destination (Join-Path $pagesDir 'publish_manifest.json') -Force

$env:WRANGLER_SEND_METRICS = 'false'
$deploySucceeded = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    & npx.cmd wrangler pages deploy $pagesDir --project-name 'bestcf-auto-stitchb9283' --branch main
    if ($LASTEXITCODE -eq 0) {
        $deploySucceeded = $true
        break
    }
    if ($attempt -lt 3) {
        Write-Warning "Cloudflare Pages deploy attempt $attempt failed; retrying in 15 seconds"
        Start-Sleep -Seconds 15
    }
}
if (-not $deploySucceeded) {
    throw 'Cloudflare Pages deploy failed after 3 attempts'
}

$onlineArtifact = Join-Path $staging "bestcf_final_online_$runId.txt"
$onlineUrl = "https://bestcf-auto-stitchb9283.pages.dev/bestcf_final.txt?run=$runId"
$onlineVerified = $false
for ($attempt = 1; $attempt -le 6; $attempt++) {
    try {
        Invoke-WebRequest -Uri $onlineUrl -Headers @{ 'Cache-Control' = 'no-cache' } -OutFile $onlineArtifact -UseBasicParsing
        $onlineSha = (Get-FileHash -LiteralPath $onlineArtifact -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($onlineSha -eq $expectedSha) {
            $onlineVerified = $true
            break
        }
        Write-Warning "Online SHA-256 is not current yet: expected=$expectedSha actual=$onlineSha"
    }
    catch {
        Write-Warning "Online verification attempt $attempt failed: $($_.Exception.Message)"
    }
    if ($attempt -lt 6) {
        Start-Sleep -Seconds 10
    }
}
if (-not $onlineVerified) {
    throw 'Cloudflare Pages online SHA-256 verification failed'
}

python (Join-Path $repo 'scripts\finalize-publish.py') `
    --db $db `
    --manifest $manifest `
    --artifact $artifact `
    --result-json (Join-Path $staging 'finalize_result.json')
Assert-NativeCommandSucceeded 'SQLite publication finalization'

$publicFinal = Join-Path $repo 'public\bestcf_final.txt'
$publicTemp = Join-Path $repo 'public\bestcf_final.txt.new'
Copy-Item -LiteralPath $artifact -Destination $publicTemp -Force
Move-Item -LiteralPath $publicTemp -Destination $publicFinal -Force
Copy-Item -LiteralPath $summary -Destination (Join-Path $repo 'public\stateful_run_summary.json') -Force
Copy-Item -LiteralPath $manifest -Destination (Join-Path $repo 'public\publish_manifest.json') -Force

python (Join-Path $repo 'bestcf_tool.py') validate-output $publicFinal --min-lines 10 --min-regions 3
Assert-NativeCommandSucceeded 'final local output validation'
Write-Host "Published run $runId; nodes=$($summaryData.selected_count); sha256=$expectedSha"
