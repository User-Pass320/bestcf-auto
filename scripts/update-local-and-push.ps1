param(
    [switch]$NoPush
)

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
    Stop-Transcript | Out-Null
    exit 0
}

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
