param(
    [switch]$NoPush
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

$logDir = Join-Path $projectRoot "bestcf_work"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logPath = Join-Path $logDir "update-local-and-push.log"
$runStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runStatePath = Join-Path $logDir ("update-local-and-push_{0}.json" -f $runStamp)
$script:CurrentStage = "initializing"
$script:RunStartedAt = Get-Date
$script:GitSafeDirectory = ($projectRoot -replace '\\','/')

function Get-GitFailureType {
    param([string]$Text)
    $value = ($Text | Out-String)
    if ($value -match '(?i)detected dubious ownership|safe\.directory') { return 'safe-directory' }
    if ($value -match '(?i)authentication failed|invalid username or token|permission denied|could not read Username') { return 'credential-or-permission' }
    if ($value -match '(?i)non-fast-forward|fetch first|rejected') { return 'non-fast-forward' }
    if ($value -match '(?i)could not resolve host|connection .*failed|network is unreachable|timed out') { return 'network' }
    if ($value -match '(?i)please tell me who you are|user\.name|user\.email') { return 'identity' }
    return 'git-error'
}

function Write-RunState {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Stage,
        [string]$Message = '',
        [string]$FailureType = '',
        [int]$ExitCode = 0
    )
    try {
        [ordered]@{
            generated_at = (Get-Date).ToString('o')
            status = $Status
            stage = $Stage
            message = $Message
            failure_type = $FailureType
            exit_code = $ExitCode
            elapsed_seconds = [math]::Round(((Get-Date) - $script:RunStartedAt).TotalSeconds, 3)
            project = $projectRoot
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $runStatePath -Encoding UTF8
    } catch {
        Write-Warning "Unable to persist run state: $($_.Exception.Message)"
    }
}

function Set-Stage {
    param([Parameter(Mandatory = $true)][string]$Name)
    $script:CurrentStage = $Name
    Write-Host "[stage] $Name"
    Write-RunState -Status 'running' -Stage $Name
}

function Invoke-GitCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [int[]]$AllowedExitCodes = @(0)
    )
    $script:CurrentStage = "git:$Stage"
    Write-Host "[stage] git:$Stage"
    $gitLines = @(& git -c ("safe.directory={0}" -f $script:GitSafeDirectory) @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = (($gitLines | ForEach-Object { $_.ToString() }) -join "`n").Trim()
    if ($text) {
        $gitLines | ForEach-Object { Write-Host ("[git:{0}] {1}" -f $Stage, $_) }
    }
    if ($AllowedExitCodes -notcontains $exitCode) {
        $failureType = Get-GitFailureType $text
        Write-RunState -Status 'failed' -Stage $script:CurrentStage -Message $text -FailureType $failureType -ExitCode $exitCode
        throw "git $Stage failed (type=$failureType, exit=$exitCode): $text"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Text = $text }
}

Start-Transcript -Path $logPath -Append | Out-Null

trap {
    $errorMessage = $_.Exception.Message
    $failureType = if ($script:CurrentStage -like 'git:*') { Get-GitFailureType $errorMessage } else { 'script-error' }
    Write-RunState -Status 'failed' -Stage $script:CurrentStage -Message $errorMessage -FailureType $failureType -ExitCode 1
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

$projectParent = Split-Path -Parent $projectRoot
$mihomoCandidates = @(
    "D:\edgetunnel-bestcf-selfdeploy\bin\mihomo-windows-amd64-compatible.exe",
    (Join-Path $projectParent "edgetunnel-bestcf-selfdeploy\bin\mihomo-windows-amd64-compatible.exe")
)
$mihomo = $mihomoCandidates |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
if (-not $mihomo) {
    $searchDirs = @(
        "D:\edgetunnel-bestcf-selfdeploy\bin",
        (Join-Path $projectParent "edgetunnel-bestcf-selfdeploy\bin")
    )
    foreach ($searchDir in $searchDirs) {
        $foundMihomo = Get-ChildItem -LiteralPath $searchDir -Recurse -Filter "mihomo*.exe" -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
        if ($foundMihomo) {
            $mihomo = $foundMihomo
            break
        }
    }
}
if (-not $mihomo -or -not (Test-Path -LiteralPath $mihomo)) {
    throw "mihomo not found in the configured local candidate paths"
}
Write-Host "Using mihomo: $mihomo"
Write-RunState -Status 'running' -Stage 'initializing' -Message ("run={0}; no_push={1}" -f $runStamp, [bool]$NoPush)
if (-not (Test-Path -LiteralPath ".\template.yaml")) {
    throw "template.yaml not found. This private file is required for local testing."
}

New-Item -ItemType Directory -Force -Path ".\public" | Out-Null

Stop-BestCFWorkerProcesses

$candidateOutput = ".\bestcf_work\bestcf_final_candidate.txt"
$verifiedOutput = ".\bestcf_work\bestcf_final_verified.txt"
$verifyDetails = ".\bestcf_work\final_true_exit_verify.csv"
$verifySummary = ".\bestcf_work\final_true_exit_verify_summary.json"
$sourceRefreshDir = ".\bestcf_work\source_refresh"
$sourceCandidateOutput = Join-Path $sourceRefreshDir "bestcf_source_candidate.txt"
$sourceMergeSummary = ".\bestcf_work\source_candidate_merge_summary.json"
$cfstPorts = @(443, 2053, 2083, 2087, 2096, 8443)

New-Item -ItemType Directory -Force -Path $sourceRefreshDir | Out-Null
Remove-Item -LiteralPath $sourceCandidateOutput -Force -ErrorAction SilentlyContinue

Set-Stage 'source-refresh'
Write-Host "Refreshing live BestCF and third-party source candidates (time budget: 240 seconds)."
Write-Host "This supplement is best-effort; CFST and the historical pool continue if source refresh fails."
python .\bestcf_tool.py `
    --profile fast `
    --source-mode legacy `
    --workdir $sourceRefreshDir `
    --template .\template.yaml `
    --mihomo $mihomo `
    --output $sourceCandidateOutput `
    --source-timeout 12 `
    --source-retries 1 `
    --source-concurrency 12 `
    --use-source-cache-quarantine `
    --geo-providers youtube,ping0 `
    --geo-concurrency 16 `
    --latency-threshold 1500 `
    --selection-mode all-regions `
    --preferred-country-min "JP:20,SG:20,US:20,HK:10,KR:5,TW:5" `
    --country-max 30 `
    --country-max-overrides "HK:20,DE:20" `
    --max-final-candidates 180 `
    --time-budget 240 `
    --time-safety-margin 20 `
    --allow-other-regions `
    --no-service-check `
    --no-hk-suppression
$sourceRefreshExit = $LASTEXITCODE
$sourceCandidateCount = 0
if ($sourceRefreshExit -eq 0 -and (Test-Path -LiteralPath $sourceCandidateOutput)) {
    $sourceCandidateCount = @(
        Get-Content -LiteralPath $sourceCandidateOutput |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    ).Count
}
if ($sourceCandidateCount -gt 0) {
    Write-Host "External source refresh completed: candidates=$sourceCandidateCount"
} else {
    Remove-Item -LiteralPath $sourceCandidateOutput -Force -ErrorAction SilentlyContinue
    Write-Warning "External source refresh produced no usable candidate output (exit=$sourceRefreshExit). Continuing with CFST pool."
}

foreach ($cfstPort in $cfstPorts) {
    Set-Stage ("cfst-update-{0}" -f $cfstPort)
    Write-Host "Running weekly CFST incremental update for port $cfstPort"
    python .\bestcf_tool.py `
        --profile balanced `
        --source-mode cfst-only `
        --pool-mode incremental `
        --pool-file edgetunnel_node_pool.csv `
        --cfst-exe .\tools\cfst\cfst.exe `
        --cfst-ip-file .\tools\cfst\ip.txt `
        --cfst-port $cfstPort `
        --cfst-pool-limits HK:60,SG:60,UNKNOWN:0 `
        --cfst-other-pool-limit 70 `
        --workdir .\bestcf_work `
        --template .\template.yaml `
        --mihomo $mihomo `
        --output $candidateOutput `
        --no-geo-cache `
        --no-geo-hint-cache `
        --geo-providers youtube,ping0 `
        --geo-concurrency 16 `
        --latency-threshold 1500 `
        --selection-mode all-regions `
        --country-max 30 `
        --country-max-overrides HK:20,DE:20 `
        --max-final-candidates 0 `
        --no-hk-suppression
    Assert-NativeCommandSucceeded "bestcf_tool.py update port $cfstPort"
}

@'
import argparse
import collections
import csv
import json
import time
from pathlib import Path

import bestcf_tool as tool

started = time.perf_counter()
workdir = Path("bestcf_work")
pool_path = workdir / "edgetunnel_node_pool.csv"
candidate_output = workdir / "bestcf_final_candidate.txt"
rows = list(csv.DictReader(pool_path.open("r", encoding="utf-8-sig", newline="")))

args = argparse.Namespace(
    selection_mode="all-regions",
    max_final_candidates=0,
    country_max=30,
    country_max_overrides={"HK": 20, "DE": 20},
    final_preferred_latency_ms=800,
    preferred_country_order=["JP", "SG", "US", "HK", "KR", "TW"],
)
results = tool.pool_rows_to_results(rows)
select_started = time.perf_counter()
final_results = tool.select_final_results(results, args)
select_elapsed = time.perf_counter() - select_started

tool.write_final_from_results(workdir / "bestcf_final.txt", final_results)
tool.write_final_from_results(candidate_output, final_results)
tool.write_region_counts(workdir / "bestcf_region_counts.csv", results, final_results)
tool.write_edgetunnel_pool_summary(workdir, rows, final_results)

summary = {
    "mode": "weekly_incremental_multiport",
    "ports": [443, 2053, 2083, 2087, 2096, 8443],
    "pool_file": str(pool_path),
    "pool_rows": len(rows),
    "pool_healthy": sum(1 for row in rows if row.get("status") == "healthy"),
    "healthy_by_country": dict(
        sorted(
            collections.Counter(
                (row.get("true_exit_country") or "UNKNOWN").upper()
                for row in rows
                if row.get("status") == "healthy"
            ).items()
        )
    ),
    "limits": {"HK": 20, "DE": 20, "other": 30, "UNKNOWN": 0},
    "final_count": len(final_results),
    "final_by_country": dict(
        sorted(collections.Counter((result.exit_country_code or "UNKNOWN").upper() for result in final_results).items())
    ),
    "select_elapsed_seconds": round(select_elapsed, 6),
    "total_elapsed_seconds": round(time.perf_counter() - started, 6),
}
(workdir / "weekly_incremental_summary.json").write_text(
    json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
'@ | python -
Assert-NativeCommandSucceeded "weekly final generation"

python .\scripts\merge-final-candidates.py `
    --primary $candidateOutput `
    --supplement $sourceCandidateOutput `
    --output $candidateOutput `
    --summary-json $sourceMergeSummary
Assert-NativeCommandSucceeded "external source candidate merge"

python .\scripts\verify-final-true-exit.py `
    --input $candidateOutput `
    --output $verifiedOutput `
    --workdir ".\bestcf_work\final_true_exit_verify" `
    --template ".\template.yaml" `
    --mihomo $mihomo `
    --providers youtube,ping0 `
    --provider-mismatch-policy ping0 `
    --geo-concurrency 16 `
    --actual-country-aliases VN:HK `
    --country-max 30 `
    --country-max-overrides HK:20,DE:20 `
    --max-final-candidates 0 `
    --min-lines 30 `
    --min-regions 3 `
    --details-csv $verifyDetails `
    --summary-json $verifySummary `
    --region-counts-csv ".\bestcf_work\bestcf_region_counts.csv"
Assert-NativeCommandSucceeded "verify-final-true-exit"

python .\bestcf_tool.py validate-output $verifiedOutput --min-lines 30 --min-regions 3
Assert-NativeCommandSucceeded "bestcf_tool.py validate-output"

@'
import json
from pathlib import Path

workdir = Path("bestcf_work")
weekly_path = workdir / "weekly_incremental_summary.json"
verify_path = workdir / "final_true_exit_verify_summary.json"
merge_path = workdir / "source_candidate_merge_summary.json"
if weekly_path.exists() and verify_path.exists():
    weekly = json.loads(weekly_path.read_text(encoding="utf-8"))
    verify = json.loads(verify_path.read_text(encoding="utf-8"))
    weekly["candidate_final_count"] = weekly.pop("final_count", None)
    weekly["candidate_final_by_country"] = weekly.pop("final_by_country", {})
    weekly["verified_final_count"] = verify.get("output_count")
    weekly["verified_final_by_country"] = verify.get("output_by_actual_country", {})
    weekly["post_verify_dropped_by_cap"] = verify.get("dropped_by_post_verify_cap")
    weekly["post_verify_dropped_unknown"] = verify.get("dropped_unknown_count")
    weekly["post_verify_dropped_mismatch"] = verify.get("dropped_mismatch_count")
    weekly["post_verify_ping0_override"] = verify.get("accepted_ping0_override_count")
    weekly["post_verify_strict_rejected"] = verify.get("strict_rejected_count")
    weekly["post_verify_dropped_by_reason"] = verify.get("dropped_by_verification_reason", {})
    weekly["post_verify_policy"] = verify.get("verification_policy")
    weekly["post_verify_country_max"] = verify.get("country_max")
    weekly["post_verify_country_max_overrides"] = verify.get("country_max_overrides", {})
    if merge_path.exists():
        weekly["external_source_merge"] = json.loads(merge_path.read_text(encoding="utf-8"))
    weekly_path.write_text(json.dumps(weekly, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
'@ | python -
Assert-NativeCommandSucceeded "weekly summary post-verify merge"

Copy-Item -LiteralPath $verifiedOutput -Destination ".\public\bestcf_final.txt" -Force

$lineCount = (Get-Content -LiteralPath ".\public\bestcf_final.txt" | Measure-Object -Line).Lines

Copy-Item -LiteralPath ".\bestcf_work\bestcf_tested.csv" -Destination ".\public\bestcf_tested.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_failed.csv" -Destination ".\public\bestcf_failed.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_sources.csv" -Destination ".\public\bestcf_sources.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_other_regions.csv" -Destination ".\public\bestcf_other_regions.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_region_counts.csv" -Destination ".\public\bestcf_region_counts.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\bestcf_geo_provider_stats.csv" -Destination ".\public\bestcf_geo_provider_stats.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\cfst_buckets_summary.csv" -Destination ".\public\cfst_buckets_summary.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\cfst_colo_consistency.csv" -Destination ".\public\cfst_colo_consistency.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\cfst_run_summary.json" -Destination ".\public\cfst_run_summary.json" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\edgetunnel_pool_summary.csv" -Destination ".\public\edgetunnel_pool_summary.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath ".\bestcf_work\weekly_incremental_summary.json" -Destination ".\public\weekly_incremental_summary.json" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $verifyDetails -Destination ".\public\final_true_exit_verify.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $verifySummary -Destination ".\public\final_true_exit_verify_summary.json" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $sourceMergeSummary -Destination ".\public\source_candidate_merge_summary.json" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath (Join-Path $sourceRefreshDir "bestcf_sources.csv") -Destination ".\public\bestcf_external_sources.csv" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath (Join-Path $sourceRefreshDir "bestcf_source_prune_candidates.csv") -Destination ".\public\bestcf_external_source_prune_candidates.csv" -Force -ErrorAction SilentlyContinue

if ($NoPush) {
    Write-Host "NoPush enabled; skipping git add/commit/push. Lines: $lineCount"
    Write-RunState -Status 'succeeded' -Stage 'no-push' -Message ("lines={0}" -f $lineCount)
    Stop-Transcript | Out-Null
    exit 0
}

Set-Stage 'git-stage'
$null = Invoke-GitCommand -Stage 'add' -Arguments @('add', '--', 'public/', 'scripts/update-local-and-push.ps1')
$diffResult = Invoke-GitCommand -Stage 'diff-index' -Arguments @('diff', '--cached', '--quiet') -AllowedExitCodes @(0, 1)
if ($diffResult.ExitCode -eq 0) {
    Write-Host "No public result changes to commit."
    Write-RunState -Status 'succeeded' -Stage 'git-noop' -Message 'No staged changes'
    Stop-Transcript | Out-Null
    exit 0
}

Set-Stage 'git-commit'
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
$null = Invoke-GitCommand -Stage 'commit' -Arguments @('commit', '-m', "Update BestCF results ($timestamp)")
Set-Stage 'git-push'
$null = Invoke-GitCommand -Stage 'push' -Arguments @('push', '--porcelain', 'origin', 'main')
Set-Stage 'git-verify-remote'
$null = Invoke-GitCommand -Stage 'fetch' -Arguments @('fetch', '--prune', 'origin', 'main')
$localHash = (Invoke-GitCommand -Stage 'local-rev' -Arguments @('rev-parse', 'HEAD')).Text.Trim()
$remoteHash = (Invoke-GitCommand -Stage 'remote-rev' -Arguments @('rev-parse', 'origin/main')).Text.Trim()
if (-not $localHash -or -not $remoteHash -or $localHash -ne $remoteHash) {
    throw "remote verification failed: local=$localHash origin/main=$remoteHash"
}

Write-RunState -Status 'succeeded' -Stage 'completed' -Message ("lines={0}; commit={1}; origin/main={2}" -f $lineCount, $localHash, $remoteHash)
Write-Host "BestCF local update pushed. Lines: $lineCount"
Stop-Transcript | Out-Null
