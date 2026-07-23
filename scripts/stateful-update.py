#!/usr/bin/env python3
"""Run one stateful SelfDeploy observation/update cycle."""

from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bestcf_tool as tool
import geo_policy
import scheduler
from state_store import StateStore, now_iso, sha256_text


def parse_country_overrides(text: str) -> dict[str, int]:
    return tool.parse_country_min(text)


class RunLock:
    def __init__(self, path: Path, stale_hours: float = 12):
        self.path = path
        self.stale_hours = stale_hours
        self.fd: int | None = None

    def __enter__(self) -> "RunLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            age = time.time() - self.path.stat().st_mtime
            if age > self.stale_hours * 3600:
                self.path.unlink()
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise RuntimeError(f"another SelfDeploy run holds the lock: {self.path}") from exc
        os.write(self.fd, f"pid={os.getpid()} started={now_iso()}\n".encode("utf-8"))
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.fd is not None:
            os.close(self.fd)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def verify_preflight(path: Path, max_age_minutes: int = 15) -> None:
    if not path.exists():
        raise RuntimeError(f"direct preflight report missing: {path}")
    report = json.loads(path.read_text(encoding="utf-8"))
    if not report.get("ok"):
        raise RuntimeError(f"direct preflight did not pass: {report.get('failures')}")
    if str((report.get("trace") or {}).get("loc") or "").upper() != "CN":
        raise RuntimeError("direct preflight trace is not CN")
    generated_at = str(report.get("generated_at") or "")
    if not generated_at:
        raise RuntimeError("direct preflight report has no generated_at timestamp")
    try:
        generated = dt.datetime.fromisoformat(generated_at)
        if generated.tzinfo is None:
            generated = generated.replace(tzinfo=dt.datetime.now().astimezone().tzinfo)
        age = dt.datetime.now().astimezone() - generated.astimezone()
    except ValueError as exc:
        raise RuntimeError("direct preflight generated_at timestamp is invalid") from exc
    if age.total_seconds() < -60 or age.total_seconds() > max(1, max_age_minutes) * 60:
        raise RuntimeError(f"direct preflight report is stale: age_seconds={age.total_seconds():.0f}")


def build_runtime_args(
    *,
    workdir: Path,
    template: Path,
    mihomo: Path,
    latency_samples: int,
    latency_threshold: int,
    geo_concurrency: int,
    base_port: int,
    controller_base_port: int,
) -> argparse.Namespace:
    parser = tool.build_arg_parser()
    args = parser.parse_args(
        [
            "--profile", "balanced",
            "--workdir", str(workdir),
            "--template", str(template),
            "--mihomo", str(mihomo),
            "--geo-providers", "youtube,ping0",
            "--geo-policy", "youtube-ping0-strict",
            "--no-geo-cache",
            "--no-geo-hint-cache",
            "--no-service-check",
            "--selection-mode", "all-regions",
            "--latency-threshold", str(latency_threshold),
            "--latency-gate", "median",
            "--latency-samples", str(latency_samples),
            "--geo-concurrency", str(geo_concurrency),
            "--base-port", str(base_port),
            "--controller-base-port", str(controller_base_port),
            "--line-id", "cn-local",
            "--no-hk-suppression",
        ]
    )
    tool.apply_profile_defaults(args)
    args.concurrency = max(1, int(args.concurrency))
    args.source_concurrency = max(1, int(args.source_concurrency))
    args.latency_concurrency = max(1, int(args.latency_concurrency))
    args.latency_samples = max(1, min(10, int(args.latency_samples)))
    args.geo_concurrency = max(1, int(args.geo_concurrency))
    args.geo_providers_resolved = ["youtube", "ping0"]
    args.cloudflare_tls_ports_resolved = []
    args.preferred_country_order = list(tool.PREFERRED_COUNTRY_ORDER)
    args.preferred_countries = set(args.preferred_country_order)
    args.allow_other_regions = True
    args.allow_unknown_region = False
    args.geo_cache_enabled = False
    args.geo_cache = {"version": tool.GEO_CACHE_VERSION, "entries": {}}
    args.geo_cache_lock = None
    args.geo_hint_cache_enabled = False
    args.geo_hint_cache = tool.empty_geo_hint_cache()
    args.geo_hint_cache_lock = None
    args.geo_hint_min_count = 1
    args.geo_hint_min_confidence = 0.67
    args.timings = {}
    args.latency_observations = {}
    args.run_started_at = time.monotonic()
    args.target_country_min = {}
    args.target_latency_threshold = {}
    args.target_refill_max_tested = {}
    args.country_max_overrides = {}
    args.geo_cap_countries_resolved = {"HK", "SG"}
    args.speed_bands_parsed = []
    args.hk_runtime_stats_lock = None
    args.hk_runtime_bucket_stats = {}
    args.hk_runtime_hk_count = 0
    args.hk_runtime_quota_skipped = 0
    args.hk_runtime_explored = 0
    workdir.mkdir(parents=True, exist_ok=True)
    tool.clean_workers(workdir)
    return args


def row_to_candidate(row: Any) -> tool.Candidate:
    return tool.Candidate(
        source=str(row["source"] or "stateful"),
        raw=str(row["raw_line"] or f"{row['endpoint']}#stateful"),
        host=str(row["host"]),
        port=int(row["port"]),
        name=f"stateful|{row['candidate_id']}",
        declared_region=str(row["assigned_country"] or row["legacy_country"] or "") or None,
        is_cloudflare=tool.is_cloudflare_host(str(row["host"])),
        parse_format="stateful",
    )


def sync_sources(store: StateStore, template_proxy: dict[str, Any], workdir: Path) -> dict[str, Any]:
    source_cache_path = workdir / tool.DEFAULT_SOURCE_CACHE_NAME
    source_cache = tool.load_source_cache(source_cache_path)
    sources = tool.build_sources(discover=True, timeout=8, source_cache=source_cache)
    rows, failures = tool.fetch_sources(sources, timeout=8, concurrency=12, retries=0)
    external_fetchers = {
        "github_v2rayfree": tool.fetch_v2rayfree_candidate_rows,
        "github_clashfree": tool.fetch_clashfree_candidate_rows,
        "github_automerge": tool.fetch_automerge_candidate_rows,
    }
    for source_name, fetcher in external_fetchers.items():
        external_rows, external_url, external_error = fetcher(timeout=8)
        sources[source_name] = external_url
        if external_rows:
            rows.extend(external_rows)
        if external_error:
            failures.append(
                {"source": source_name, "url": external_url, "status": "source_fetch_failed", "error": external_error}
            )
    parsed, parse_failures, _source_stats = tool.parse_candidates(rows, sources)
    tool.classify_candidate_domains(parsed, concurrency=12)
    parsed = tool.expand_cloudflare_candidates(parsed, [443, 2053, 2083, 2087, 2096, 8443])
    lines_by_source: dict[str, list[str]] = collections.defaultdict(list)
    for source, line in rows:
        lines_by_source[source].append(line)
    new_by_source: collections.Counter[str] = collections.Counter()
    created = 0
    for candidate in parsed:
        _candidate_id, _fingerprint, is_new = store.upsert_candidate(
            host=candidate.host,
            port=candidate.port,
            template_proxy=template_proxy,
            source=candidate.source,
            raw_line=candidate.raw,
        )
        if is_new:
            created += 1
            new_by_source[candidate.source] += 1
    failed_sources = {str(item.get("source") or "") for item in failures}
    timestamp = now_iso()
    for source_name, source_url in sources.items():
        source_lines = lines_by_source.get(source_name, [])
        store.record_source_snapshot(
            source_name=source_name,
            source_url=source_url,
            content_hash=sha256_text("\n".join(source_lines)),
            fetch_status="failed" if source_name in failed_sources else "ok",
            candidate_count=len(source_lines),
            new_candidate_count=new_by_source[source_name],
            fetched_at=timestamp,
        )
    return {
        "source_count": len(sources),
        "raw_row_count": len(rows),
        "parsed_candidate_count": len(parsed),
        "new_candidate_count": created,
        "fetch_failure_count": len(failures),
        "parse_failure_count": len(parse_failures),
    }


def run_cfst_rotation(
    store: StateStore,
    template_proxy: dict[str, Any],
    *,
    day: dt.date,
    root_workdir: Path,
    cfst_exe: Path,
    cfst_ip_file: Path,
) -> dict[str, Any]:
    ports = scheduler.cfst_port_group(day)
    total_new = 0
    per_port: dict[str, Any] = {}
    for port in ports:
        port_workdir = root_workdir / "cfst_rotation" / str(port)
        args = tool.build_arg_parser().parse_args(
            [
                "--profile", "balanced",
                "--source-mode", "cfst-only",
                "--workdir", str(port_workdir),
                "--cfst-exe", str(cfst_exe),
                "--cfst-ip-file", str(cfst_ip_file),
                "--cfst-port", str(port),
                "--cfst-pool-limits", "HK:60,SG:60,UNKNOWN:0",
                "--cfst-other-pool-limit", "70",
            ]
        )
        tool.apply_profile_defaults(args)
        args.cfst_threads = max(1, min(1000, int(args.cfst_threads)))
        args.cfst_latency_tests = max(1, int(args.cfst_latency_tests))
        args.cfst_httping_tests = max(1, int(args.cfst_httping_tests))
        args.cfst_latency_threshold = max(1, int(args.cfst_latency_threshold))
        args.cfst_httping_threshold = max(1, int(args.cfst_httping_threshold))
        args.cfst_timeout = max(30, int(args.cfst_timeout))
        args.cfst_httping_retries = max(1, int(args.cfst_httping_retries))
        args.cfst_httping_retry_delay = max(0.0, float(args.cfst_httping_retry_delay))
        args.cfst_other_pool_limit = max(0, int(args.cfst_other_pool_limit))
        args.timings = {}
        candidates = tool.build_cfst_only_candidates(port_workdir, args)
        new_count = 0
        for candidate in candidates:
            _candidate_id, _fingerprint, created = store.upsert_candidate(
                host=candidate.host,
                port=candidate.port,
                template_proxy=template_proxy,
                source=candidate.source,
                raw_line=candidate.raw,
            )
            new_count += int(created)
        total_new += new_count
        per_port[str(port)] = {"candidate_count": len(candidates), "new_candidate_count": new_count}
    return {"ports": list(ports), "new_candidate_count": total_new, "per_port": per_port}


def run_geo(
    plan: list[scheduler.PlannedCandidate],
    *,
    template_proxy: dict[str, Any],
    template_path: Path,
    mihomo: Path,
    workdir: Path,
    geo_concurrency: int,
    base_port: int,
) -> tuple[list[tool.TestResult], dict[tuple[str, int], scheduler.PlannedCandidate], argparse.Namespace]:
    mapping: dict[tuple[str, int], scheduler.PlannedCandidate] = {}
    candidates: list[tool.Candidate] = []
    for item in plan:
        candidate = row_to_candidate(item.row)
        if candidate.key in mapping:
            continue
        mapping[candidate.key] = item
        candidates.append(candidate)
    args = build_runtime_args(
        workdir=workdir,
        template=template_path,
        mihomo=mihomo,
        latency_samples=1,
        latency_threshold=1500,
        geo_concurrency=geo_concurrency,
        base_port=base_port,
        controller_base_port=base_port + 1000,
    )
    items = [(f"state-{index:04d}", candidate, 0) for index, candidate in enumerate(candidates)]
    results = tool.run_geo_batch(items, template_proxy, args, "stateful_strict")
    return results, mapping, args


def required_valid_latency_samples(requested: int) -> int:
    return max(1, int(requested))


def run_latency(
    candidates: list[tool.Candidate],
    *,
    samples: int,
    template_proxy: dict[str, Any],
    template_path: Path,
    mihomo: Path,
    workdir: Path,
    base_port: int,
) -> tuple[dict[tuple[str, int], tool.TestResult], dict[tuple[str, int], dict[str, Any]], dict[str, float]]:
    if not candidates:
        return {}, {}, {}
    args = build_runtime_args(
        workdir=workdir,
        template=template_path,
        mihomo=mihomo,
        latency_samples=samples,
        latency_threshold=1500,
        geo_concurrency=1,
        base_port=base_port,
        controller_base_port=base_port + 1000,
    )
    started = time.monotonic()
    eligible, failures = tool.run_latency_tests(candidates, template_proxy, args)
    elapsed = time.monotonic() - started
    result_map: dict[tuple[str, int], tool.TestResult] = {
        candidate.key: tool.TestResult(candidate, True, "latency_ok", latency_ms=float(delay))
        for _proxy_name, candidate, delay in eligible
    }
    result_map.update({result.candidate.key: result for result in failures})
    if samples > 1:
        for candidate in candidates:
            observation = args.latency_observations.get(candidate.key, {})
            valid_samples = len(observation.get("samples") or [])
            current = result_map.get(candidate.key)
            required_samples = required_valid_latency_samples(samples)
            if current and current.ok and valid_samples < required_samples:
                result_map[candidate.key] = tool.TestResult(
                    candidate,
                    False,
                    "latency_incomplete",
                    f"valid latency samples={valid_samples} < required={required_samples}",
                )
    return result_map, dict(args.latency_observations), {"latency_seconds": elapsed}


def guard_latency_batch(results: dict[tuple[str, int], tool.TestResult], *, minimum: int = 10) -> None:
    if len(results) < minimum:
        return
    success = sum(1 for result in results.values() if result.ok)
    if success / len(results) <= 0.10:
        raise RuntimeError(
            f"batch latency environment invalid: results={len(results)} success={success}"
        )


def apply_batch_results(
    store: StateStore,
    *,
    run_id: int,
    geo_results: list[tool.TestResult],
    plan_map: dict[tuple[str, int], scheduler.PlannedCandidate],
    latency_results: dict[tuple[str, int], tool.TestResult],
    latency_observations: dict[tuple[str, int], dict[str, Any]],
) -> tuple[int, int]:
    success = 0
    failure = 0
    for geo_result in geo_results:
        planned = plan_map.get(geo_result.candidate.key)
        if planned is None:
            continue
        candidate_id = int(planned.row["candidate_id"])
        decision_status = geo_result.geo_decision_status or geo_result.status
        observations = geo_policy.parse_evidence(geo_result.geo_evidence)
        for observation in observations:
            store.record_geo_observation(
                run_id=run_id,
                candidate_id=candidate_id,
                provider=observation.provider,
                attempt=observation.attempt,
                raw_country=observation.raw_country or observation.country,
                normalized_country=geo_policy.normalize_country(observation.country),
                exit_ip=geo_result.exit_ip if observation.provider == "ping0" else None,
                status=observation.status,
                policy_version=geo_policy.POLICY_VERSION,
            )
        latency_result = latency_results.get(geo_result.candidate.key)
        latency_observation = latency_observations.get(geo_result.candidate.key, {})
        latency_ok = bool(latency_result and latency_result.ok)
        median = latency_observation.get("median_ms")
        p90 = latency_observation.get("p90_ms")
        samples = list(latency_observation.get("samples") or [])
        for index, sample in enumerate(samples, start=1):
            store.record_latency_observation(
                run_id=run_id,
                candidate_id=candidate_id,
                sample_index=index,
                latency_ms=float(sample),
                median_ms=float(median) if median is not None else None,
                p90_ms=float(p90) if p90 is not None else None,
                sample_count=len(samples),
                status="latency_ok" if latency_ok else "latency_failed",
                policy_version=geo_policy.POLICY_VERSION,
                error="" if latency_ok else str(latency_result.error if latency_result else "not tested"),
            )
        # During the baseline gate, confirmed HK needs no three-sample delay to be safely excluded from non-HK.
        if planned.test_level == "gate" and decision_status == "confirmed_hk" and latency_result is None:
            latency_ok = True
        new_state = store.apply_strict_result(
            candidate_id=candidate_id,
            run_id=run_id,
            decision_status=decision_status,
            country=geo_result.exit_country_code,
            exit_ip=geo_result.exit_ip,
            latency_ok=latency_ok if decision_status in {"confirmed_non_hk", "confirmed_hk"} else False,
            latency_median_ms=float(median) if median is not None else None,
            latency_p90_ms=float(p90) if p90 is not None else None,
            latency_sample_count=len(samples),
            fail_reason=str(latency_result.error if latency_result and not latency_result.ok else geo_result.error or ""),
        )
        if new_state in {"hot", "probation"}:
            success += 1
        else:
            failure += 1
    return success, failure


def write_audit_report(
    path: Path,
    geo_results: list[tool.TestResult],
    plan_map: dict[tuple[str, int], scheduler.PlannedCandidate],
    latency_observations: dict[tuple[str, int], dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        fieldnames = [
            "candidate_id", "fingerprint", "endpoint", "legacy_country",
            "youtube_raw_country", "youtube_country", "ping0_raw_country", "ping0_country",
            "decision", "actual_country", "canonical_exit_ip", "latency_samples", "latency_median_ms",
            "latency_p90_ms", "source", "raw_line",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in sorted(geo_results, key=lambda item: item.candidate.endpoint):
            planned = plan_map[result.candidate.key]
            observations = geo_policy.parse_evidence(result.geo_evidence)
            primary = {row.provider: row.country for row in observations}
            raw_primary = {row.provider: row.raw_country for row in observations}
            latency = latency_observations.get(result.candidate.key, {})
            writer.writerow(
                {
                    "candidate_id": planned.row["candidate_id"],
                    "fingerprint": planned.row["fingerprint"],
                    "endpoint": result.candidate.endpoint,
                    "legacy_country": planned.row["legacy_country"] or "",
                    "youtube_raw_country": raw_primary.get("youtube") or "",
                    "youtube_country": primary.get("youtube") or "",
                    "ping0_raw_country": raw_primary.get("ping0") or "",
                    "ping0_country": primary.get("ping0") or "",
                    "decision": result.geo_decision_status or result.status,
                    "actual_country": result.exit_country_code or "",
                    "canonical_exit_ip": result.exit_ip or "",
                    "latency_samples": "|".join(str(value) for value in latency.get("samples") or []),
                    "latency_median_ms": latency.get("median_ms") or "",
                    "latency_p90_ms": latency.get("p90_ms") or "",
                    "source": planned.row["source"],
                    "raw_line": planned.row["raw_line"],
                }
            )


def current_run_publishable_rows(store: StateStore, run_id: int, mode: str) -> list[Any]:
    rows = store.rows()
    selected: list[Any] = []
    for row in rows:
        country = str(row["assigned_country"] or "").upper()
        if (
            country == "HK"
            and mode == "wednesday"
            and bool(row["published"])
            and str(row["last_decision_status"] or "") == "confirmed_hk"
            and int(row["latency_sample_count"] or 0) >= 3
        ):
            selected.append(row)
        elif int(row["last_run_id"] or 0) == int(run_id):
            selected.append(row)
    return selected


def write_final(path: Path, selected: list[Any]) -> tuple[str, list[tuple[int, str, str, int]]]:
    counters: collections.Counter[str] = collections.Counter()
    lines: list[str] = []
    history: list[tuple[int, str, str, int]] = []
    for row in selected:
        country = str(row["assigned_country"] or "").upper()
        label = tool.country_name(country)
        counters[country] += 1
        lines.append(f"{row['endpoint']}#{label}-{counters[country]}")
        history.append((int(row["candidate_id"]), country, label, counters[country]))
    payload = "\n".join(lines) + ("\n" if lines else "")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8", newline="\n")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest().upper(), history


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["prebuild", "wednesday", "sunday", "shadow", "manual"], required=True)
    parser.add_argument("--effective-mode", choices=["wednesday", "sunday"], default=None)
    parser.add_argument("--db", default="bestcf_work/bestcf_observations.sqlite")
    parser.add_argument("--workdir", default="bestcf_work/stateful")
    parser.add_argument("--template", default="template.yaml")
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--preflight-report", required=True)
    parser.add_argument("--preflight-max-age-minutes", type=int, default=15)
    parser.add_argument("--output", default="bestcf_work/staging/bestcf_final.txt")
    parser.add_argument("--summary-json", default="bestcf_work/stateful_run_summary.json")
    parser.add_argument("--publish-manifest", default="bestcf_work/staging/publish_manifest.json")
    parser.add_argument("--soft-limit", type=int, default=600)
    parser.add_argument("--hard-limit", type=int, default=800)
    parser.add_argument("--hk-archive-sample", type=int, default=100)
    parser.add_argument("--country-max", type=int, default=30)
    parser.add_argument("--country-max-overrides", default="HK:20,DE:20")
    parser.add_argument("--exit-ip-max", type=int, default=3)
    parser.add_argument("--geo-concurrency", type=int, default=16)
    parser.add_argument("--skip-source-sync", action="store_true")
    parser.add_argument("--skip-cfst", action="store_true")
    parser.add_argument("--cfst-exe", default="tools/cfst/cfst.exe")
    parser.add_argument("--cfst-ip-file", default="tools/cfst/ip.txt")
    parser.add_argument("--min-lines", type=int, default=10)
    parser.add_argument("--min-regions", type=int, default=3)
    args = parser.parse_args()

    mode = args.mode
    if args.effective_mode and mode not in {"shadow", "manual"}:
        raise RuntimeError("--effective-mode is only valid with shadow or manual mode")
    effective_mode = args.effective_mode or mode
    if mode == "manual" and not args.effective_mode:
        effective_mode = "sunday"
    if mode == "shadow" and not args.effective_mode:
        effective_mode = "wednesday" if dt.datetime.now().astimezone().weekday() <= 3 else "sunday"
    db_path = Path(args.db)
    root_workdir = Path(args.workdir)
    template_path = Path(args.template)
    mihomo_path = Path(args.mihomo)
    preflight_path = Path(args.preflight_report)
    output_path = Path(args.output)
    summary_path = Path(args.summary_json)
    manifest_path = Path(args.publish_manifest)
    lock_path = db_path.parent / "stateful_update.lock"

    verify_preflight(preflight_path, max_age_minutes=args.preflight_max_age_minutes)
    if not db_path.exists():
        raise RuntimeError(f"state database missing; run migration first: {db_path}")
    template_proxy = tool.load_template(template_path)
    started = time.monotonic()
    stage_timings: dict[str, float] = {}
    source_summary: dict[str, Any] = {}
    cfst_summary: dict[str, Any] = {}

    with RunLock(lock_path), StateStore(db_path) as store:
        run_id = store.start_run(mode, geo_policy.POLICY_VERSION)
        try:
            if mode not in {"prebuild", "shadow"} and not args.skip_source_sync:
                stage = time.monotonic()
                source_summary = sync_sources(store, template_proxy, db_path.parent)
                stage_timings["source_sync"] = time.monotonic() - stage
            if effective_mode == "sunday" and mode not in {"prebuild", "shadow"} and not args.skip_cfst:
                stage = time.monotonic()
                cfst_summary = run_cfst_rotation(
                    store,
                    template_proxy,
                    day=dt.datetime.now().astimezone().date(),
                    root_workdir=root_workdir,
                    cfst_exe=Path(args.cfst_exe),
                    cfst_ip_file=Path(args.cfst_ip_file),
                )
                stage_timings["cfst_rotation"] = time.monotonic() - stage

            rows = store.rows()
            plan_mode = "prebuild" if mode == "prebuild" else effective_mode
            plan = scheduler.build_test_plan(
                rows,
                mode=plan_mode,
                soft_limit=max(1, args.soft_limit),
                hard_limit=max(1, args.hard_limit),
                hk_archive_sample=max(0, args.hk_archive_sample),
            )
            store.connection.execute("UPDATE test_runs SET candidate_count=? WHERE run_id=?", (len(plan), run_id))
            if not plan:
                raise RuntimeError("scheduler selected no candidates")

            stage = time.monotonic()
            geo_results, plan_map, _geo_args = run_geo(
                plan,
                template_proxy=template_proxy,
                template_path=template_path,
                mihomo=mihomo_path,
                workdir=root_workdir / f"run_{run_id}" / "geo",
                geo_concurrency=max(1, args.geo_concurrency),
                base_port=54000,
            )
            stage_timings["strict_geo"] = time.monotonic() - stage
            system_failures = sum(
                1 for result in geo_results if result.status in {"mihomo_start_failed", "select_proxy_failed", "exception"}
            )
            unknown = sum(1 for result in geo_results if (result.geo_decision_status or result.status) == "geo_unknown")
            if len(geo_results) >= 10 and (system_failures / len(geo_results) >= 0.8 or unknown / len(geo_results) >= 0.9):
                raise RuntimeError(
                    f"batch environment invalid: results={len(geo_results)} system_failures={system_failures} geo_unknown={unknown}"
                )

            full_candidates: list[tool.Candidate] = []
            light_candidates: list[tool.Candidate] = []
            for result in geo_results:
                decision = result.geo_decision_status or result.status
                if decision not in {"confirmed_non_hk", "confirmed_hk"}:
                    continue
                planned = plan_map[result.candidate.key]
                if planned.test_level == "gate" and decision == "confirmed_hk":
                    continue
                if planned.test_level in {"full", "gate"}:
                    full_candidates.append(result.candidate)
                else:
                    light_candidates.append(result.candidate)

            stage = time.monotonic()
            full_results, full_obs, _ = run_latency(
                full_candidates,
                samples=3,
                template_proxy=template_proxy,
                template_path=template_path,
                mihomo=mihomo_path,
                workdir=root_workdir / f"run_{run_id}" / "latency_full",
                base_port=55000,
            )
            light_results, light_obs, _ = run_latency(
                light_candidates,
                samples=1,
                template_proxy=template_proxy,
                template_path=template_path,
                mihomo=mihomo_path,
                workdir=root_workdir / f"run_{run_id}" / "latency_light",
                base_port=56000,
            )
            stage_timings["latency"] = time.monotonic() - stage
            latency_results = {**light_results, **full_results}
            latency_observations = {**light_obs, **full_obs}
            guard_latency_batch(latency_results)

            success_count, failure_count = apply_batch_results(
                store,
                run_id=run_id,
                geo_results=geo_results,
                plan_map=plan_map,
                latency_results=latency_results,
                latency_observations=latency_observations,
            )

            full_verified_ids = {
                int(item.row["candidate_id"])
                for item in plan
                if item.test_level in {"full", "gate"}
            }

            # A light-tested hot candidate is never published directly.  Re-run the strict
            # geo gate and three latency samples in the same cycle before promotion.
            if mode not in {"prebuild", "shadow"}:
                promotion_started = time.monotonic()
                for promotion_round in range(1, 4):
                    current_rows = current_run_publishable_rows(store, run_id, effective_mode)
                    provisional = scheduler.select_for_publish(
                        current_rows,
                        country_max=max(0, args.country_max),
                        country_overrides=parse_country_overrides(args.country_max_overrides),
                        exit_ip_max=max(0, args.exit_ip_max),
                    )
                    needs_full = [
                        row for row in provisional
                        if int(row["candidate_id"]) not in full_verified_ids
                        and not (
                            effective_mode == "wednesday"
                            and str(row["assigned_country"] or "").upper() == "HK"
                            and bool(row["published"])
                            and int(row["latency_sample_count"] or 0) >= 3
                        )
                    ]
                    if not needs_full:
                        break
                    promotion_plan = [
                        scheduler.PlannedCandidate(row, 0, "full", f"promotion_round_{promotion_round}")
                        for row in needs_full
                    ]
                    promotion_geo, promotion_map, _ = run_geo(
                        promotion_plan,
                        template_proxy=template_proxy,
                        template_path=template_path,
                        mihomo=mihomo_path,
                        workdir=root_workdir / f"run_{run_id}" / f"promotion_{promotion_round}_geo",
                        geo_concurrency=max(1, args.geo_concurrency),
                        base_port=57000 + promotion_round * 200,
                    )
                    promotion_system_failures = sum(
                        1 for result in promotion_geo
                        if result.status in {"mihomo_start_failed", "select_proxy_failed", "exception"}
                    )
                    promotion_unknown = sum(
                        1 for result in promotion_geo
                        if (result.geo_decision_status or result.status) == "geo_unknown"
                    )
                    if len(promotion_geo) >= 5 and (
                        promotion_system_failures / len(promotion_geo) >= 0.8
                        or promotion_unknown / len(promotion_geo) >= 0.9
                    ):
                        raise RuntimeError(
                            "promotion environment invalid: "
                            f"results={len(promotion_geo)} system_failures={promotion_system_failures} "
                            f"geo_unknown={promotion_unknown}"
                        )
                    promotion_candidates = [
                        result.candidate
                        for result in promotion_geo
                        if (result.geo_decision_status or result.status) in {"confirmed_non_hk", "confirmed_hk"}
                    ]
                    promotion_latency, promotion_obs, _ = run_latency(
                        promotion_candidates,
                        samples=3,
                        template_proxy=template_proxy,
                        template_path=template_path,
                        mihomo=mihomo_path,
                        workdir=root_workdir / f"run_{run_id}" / f"promotion_{promotion_round}_latency",
                        base_port=58000 + promotion_round * 200,
                    )
                    guard_latency_batch(promotion_latency, minimum=5)
                    promoted_ok, promoted_failed = apply_batch_results(
                        store,
                        run_id=run_id,
                        geo_results=promotion_geo,
                        plan_map=promotion_map,
                        latency_results=promotion_latency,
                        latency_observations=promotion_obs,
                    )
                    success_count += promoted_ok
                    failure_count += promoted_failed
                    full_verified_ids.update(int(row["candidate_id"]) for row in needs_full)
                stage_timings["promotion"] = time.monotonic() - promotion_started

            if mode == "prebuild":
                audit_path = db_path.parent / "prebuild_nonhk_audit.csv"
                write_audit_report(audit_path, geo_results, plan_map, latency_observations)

            publish_count = 0
            artifact_sha = None
            selected: list[Any] = []
            if mode not in {"prebuild", "shadow"}:
                current_rows = current_run_publishable_rows(store, run_id, effective_mode)
                selected = scheduler.select_for_publish(
                    current_rows,
                    country_max=max(0, args.country_max),
                    country_overrides=parse_country_overrides(args.country_max_overrides),
                    exit_ip_max=max(0, args.exit_ip_max),
                )
                artifact_sha, history = write_final(output_path, selected)
                ok, message = tool.validate_final_output(
                    output_path,
                    min_lines=max(1, args.min_lines),
                    min_regions=max(1, args.min_regions),
                )
                if not ok:
                    raise RuntimeError(message)
                publish_count = len(selected)
                manifest = {
                    "manifest_version": 1,
                    "run_id": run_id,
                    "effective_mode": effective_mode,
                    "policy_version": geo_policy.POLICY_VERSION,
                    "artifact_sha256": artifact_sha,
                    "selected": [
                        {
                            "candidate_id": int(row["candidate_id"]),
                            "fingerprint": str(row["fingerprint"]),
                            "endpoint": str(row["endpoint"]),
                            "country": str(row["assigned_country"] or "").upper(),
                            "exit_ip": str(row["canonical_exit_ip"] or ""),
                            "latency_median_ms": row["latency_median_ms"],
                            "latency_p90_ms": row["latency_p90_ms"],
                            "geo_decision_status": str(row["last_decision_status"] or ""),
                            "country_success_streak": int(row["country_success_streak"] or 0),
                            "hk_seen_count": int(row["hk_seen_count"] or 0),
                            "label": history[index][2],
                            "rank": history[index][3],
                        }
                        for index, row in enumerate(selected)
                    ],
                }
                manifest_path.parent.mkdir(parents=True, exist_ok=True)
                manifest_path.write_text(
                    json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

            stage_timings["total"] = time.monotonic() - started
            counts = store.counts()
            summary = {
                "run_id": run_id,
                "mode": mode,
                "effective_mode": effective_mode,
                "policy_version": geo_policy.POLICY_VERSION,
                "candidate_count": len(plan),
                "success_count": success_count,
                "failure_count": failure_count,
                "selected_count": publish_count,
                "artifact_sha256": artifact_sha,
                "source_sync": source_summary,
                "cfst": cfst_summary,
                "state_counts": counts,
                "stage_timings": stage_timings,
                "output": str(output_path) if publish_count else None,
            }
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            store.finish_run(
                run_id,
                result="observed" if mode in {"prebuild", "shadow"} else "staged",
                direct_preflight_ok=True,
                success_count=success_count,
                failure_count=failure_count,
                published_count=0,
                stage_timings=stage_timings,
                artifact_sha256=artifact_sha,
            )
            print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        except Exception as exc:
            store.connection.rollback()
            store.finish_run(
                run_id,
                result=f"failed: {exc}",
                direct_preflight_ok=True,
                stage_timings={**stage_timings, "total": time.monotonic() - started},
            )
            raise


if __name__ == "__main__":
    raise SystemExit(main())
