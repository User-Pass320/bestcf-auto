#!/usr/bin/env python3
"""Import the current CSV assets into the stateful observation database."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bestcf_tool as tool
import geo_policy
from state_store import StateStore, now_iso, sha256_text


NON_HK_EXCLUDED = {"", "HK", "VN", "UNKNOWN", "OTHER"}


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def as_int(value: Any) -> int:
    try:
        return int(str(value or "0"))
    except ValueError:
        return 0


def as_float(value: Any) -> float | None:
    try:
        return float(str(value)) if str(value or "").strip() else None
    except ValueError:
        return None


def normalized(code: Any) -> str:
    return geo_policy.normalize_country(str(code or "")) or ""


def is_non_hk(code: Any) -> bool:
    return normalized(code) not in NON_HK_EXCLUDED


def endpoint_candidate(endpoint: str, label: str, source: str = "migration") -> tool.Candidate | None:
    return tool.parse_candidate(source, f"{endpoint}#{label or source}")


def published_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    if not path.exists():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip().split("|", 1)[0]
        if not line or "#" not in line:
            continue
        endpoint, label = line.rsplit("#", 1)
        label = label.rsplit("-", 1)[0]
        candidate = endpoint_candidate(endpoint, label, "published_legacy")
        if candidate:
            rows[candidate.endpoint.lower()] = (tool.country_code_from_text(label) or "").upper()
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", default="bestcf_work")
    parser.add_argument("--public-dir", default="public")
    parser.add_argument("--template", default="template.yaml")
    parser.add_argument("--db", default=None)
    parser.add_argument("--baseline-output", default=None)
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()

    workdir = Path(args.workdir)
    public_dir = Path(args.public_dir)
    db_path = Path(args.db) if args.db else workdir / "bestcf_observations.sqlite"
    baseline_path = Path(args.baseline_output) if args.baseline_output else workdir / "prebuild_nonhk_candidates.csv"
    if args.reset and db_path.exists():
        db_path.unlink()
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(db_path) + suffix)
            if sidecar.exists():
                sidecar.unlink()
    if db_path.exists() and not args.reset:
        raise SystemExit(f"database already exists; pass --reset for a new migration: {db_path}")

    template_path = Path(args.template)
    template_proxy = tool.load_template(template_path)
    pool_path = workdir / "edgetunnel_node_pool_cn-local.csv"
    latency_path = workdir / "bestcf_latency.csv"
    tested_path = workdir / "bestcf_tested.csv"
    verify_path = public_dir / "final_true_exit_verify_cn-local.csv"
    final_path = public_dir / "bestcf_final.txt"
    pool_rows = read_csv(pool_path)
    latency_rows = read_csv(latency_path)
    tested_rows = read_csv(tested_path)
    verify_rows = read_csv(verify_path)
    published = published_rows(final_path)

    latency_by_endpoint = {str(row.get("endpoint") or "").lower(): row for row in latency_rows}
    tested_by_endpoint = {str(row.get("endpoint") or "").lower(): row for row in tested_rows}
    verify_by_endpoint = {str(row.get("endpoint") or "").lower(): row for row in verify_rows}

    baseline_endpoints: set[str] = set()
    baseline_reasons: dict[str, set[str]] = {}

    def mark_baseline(endpoint: str, reason: str) -> None:
        key = endpoint.lower()
        baseline_endpoints.add(key)
        baseline_reasons.setdefault(key, set()).add(reason)

    for row in pool_rows:
        endpoint = str(row.get("endpoint") or "")
        if is_non_hk(row.get("true_exit_country")):
            mark_baseline(endpoint, "pool_true_non_hk")
        if is_non_hk(row.get("declared_country")):
            mark_baseline(endpoint, "pool_declared_non_hk")
    for row in verify_rows:
        endpoint = str(row.get("endpoint") or "")
        if is_non_hk(row.get("actual_country")):
            mark_baseline(endpoint, "final_verify_non_hk")
        if is_non_hk(row.get("expected_country")):
            mark_baseline(endpoint, "final_expected_non_hk")
    for endpoint, country in published.items():
        if is_non_hk(country):
            mark_baseline(endpoint, "published_non_hk")

    candidate_ids: dict[str, int] = {}
    migration_timestamp = now_iso()
    with StateStore(db_path) as store:
        store.set_metadata("migration_started_at", migration_timestamp)
        store.set_metadata("migration_policy", "legacy_assets_plus_prebuild_baseline_v1")
        store.set_metadata("template_sha256", sha256_text(template_path.read_text(encoding="utf-8")))

        def import_candidate(candidate: tool.Candidate, source_row: dict[str, Any] | None = None) -> int:
            source_row = source_row or {}
            candidate_id, _fingerprint, _created = store.upsert_candidate(
                host=candidate.host,
                port=candidate.port,
                template_proxy=template_proxy,
                source=str(source_row.get("source") or candidate.source or "legacy"),
                raw_line=str(source_row.get("raw_line") or candidate.raw or ""),
                first_seen_at=str(source_row.get("first_seen_at") or migration_timestamp),
                last_seen_at=str(source_row.get("last_seen_at") or migration_timestamp),
            )
            candidate_ids[candidate.endpoint.lower()] = candidate_id
            return candidate_id

        for row in pool_rows:
            candidate = endpoint_candidate(str(row.get("endpoint") or ""), "legacy_pool", str(row.get("source") or "legacy_pool"))
            if not candidate:
                continue
            candidate_id = import_candidate(candidate, row)
            endpoint_key = candidate.endpoint.lower()
            verify = verify_by_endpoint.get(endpoint_key, {})
            tested = tested_by_endpoint.get(endpoint_key, {})
            latency = latency_by_endpoint.get(endpoint_key, {})
            published_country = published.get(endpoint_key, "")
            final_country = normalized(verify.get("actual_country")) or normalized(row.get("true_exit_country"))
            legacy_country = final_country
            is_published = endpoint_key in published
            in_verify = endpoint_key in verify_by_endpoint
            old_status = str(row.get("status") or "")
            if is_published:
                state = "active_legacy"
            elif in_verify:
                state = "hot_legacy"
            elif old_status == "healthy" and final_country == "HK":
                state = "archive_legacy"
            elif old_status == "healthy":
                state = "observed_once_legacy"
            elif old_status == "unresolved":
                state = "geo_unknown"
            else:
                state = "cooldown_legacy"
            evidence = str(verify.get("geo_evidence") or tested.get("geo_evidence") or row.get("geo_evidence") or "")
            hk_seen = 1 if geo_policy.legacy_primary_hk_seen(evidence) else 0
            median = as_float(latency.get("latency_median_ms"))
            if median is None:
                median = as_float(row.get("proxy_latency_ms"))
            p90 = as_float(latency.get("latency_p90_ms"))
            if p90 is None:
                p90 = as_float(row.get("proxy_latency_p90_ms"))
            sample_count = as_int(latency.get("latency_sample_count") or row.get("latency_sample_count"))
            store.update_legacy_state(
                candidate_id,
                state=state,
                baseline_candidate=1 if endpoint_key in baseline_endpoints else 0,
                assigned_country=published_country or final_country or None,
                legacy_country=legacy_country or None,
                last_decision_status="legacy",
                country_success_streak=0,
                strict_success_count=0,
                country_confidence=0,
                hk_seen_count=hk_seen,
                last_hk_seen_at=str(row.get("last_tested_at") or migration_timestamp) if hk_seen else None,
                last_tested_at=str(row.get("last_tested_at") or "") or None,
                last_success_at=str(row.get("last_success_at") or "") or None,
                success_count=as_int(row.get("success_count")),
                fail_count=as_int(row.get("fail_count")),
                consecutive_fail_count=as_int(row.get("consecutive_fail_count")),
                latency_median_ms=median,
                latency_p90_ms=p90,
                latency_sample_count=sample_count,
                canonical_exit_ip=str(verify.get("exit_ip") or row.get("exit_ip") or "") or None,
                published=1 if is_published else 0,
                last_published_at=migration_timestamp if is_published else None,
                fail_reason=str(row.get("fail_reason") or ""),
            )
            if median is not None or p90 is not None:
                store.record_latency_observation(
                    candidate_id=candidate_id,
                    median_ms=median,
                    p90_ms=p90,
                    sample_count=sample_count,
                    status=str(latency.get("latency_status") or old_status or "legacy"),
                    policy_version="legacy_aggregate",
                    observed_at=str(row.get("last_tested_at") or migration_timestamp),
                    error=str(latency.get("error") or ""),
                )
            for observation in geo_policy.parse_evidence(evidence):
                store.record_geo_observation(
                    candidate_id=candidate_id,
                    provider=observation.provider,
                    attempt=observation.attempt,
                    raw_country=observation.raw_country or observation.country,
                    normalized_country=geo_policy.normalize_country(observation.country),
                    exit_ip=str(verify.get("exit_ip") or row.get("exit_ip") or "") or None,
                    status=observation.status,
                    policy_version="legacy_evidence",
                    observed_at=str(row.get("last_tested_at") or migration_timestamp),
                )

        # Preserve endpoints present in final verification/public output but absent from the rolling pool.
        for verify in verify_rows:
            endpoint = str(verify.get("endpoint") or "")
            candidate = endpoint_candidate(endpoint, str(verify.get("label") or "legacy_verify"), "legacy_verify")
            if not candidate or candidate.endpoint.lower() in candidate_ids:
                continue
            candidate_id = import_candidate(candidate)
            endpoint_key = candidate.endpoint.lower()
            country = normalized(verify.get("actual_country"))
            evidence = str(verify.get("geo_evidence") or "")
            is_published = endpoint_key in published
            store.update_legacy_state(
                candidate_id,
                state="active_legacy" if is_published else "hot_legacy",
                baseline_candidate=1 if endpoint_key in baseline_endpoints else 0,
                assigned_country=published.get(endpoint_key) or country or None,
                legacy_country=country or None,
                last_decision_status="legacy",
                hk_seen_count=1 if geo_policy.legacy_primary_hk_seen(evidence) else 0,
                canonical_exit_ip=str(verify.get("exit_ip") or "") or None,
                published=1 if is_published else 0,
                last_published_at=migration_timestamp if is_published else None,
            )

        # A published endpoint missing from both inputs must still be retained.
        for endpoint, country in published.items():
            if endpoint in candidate_ids:
                continue
            candidate = endpoint_candidate(endpoint, country or "published", "published_legacy")
            if not candidate:
                continue
            candidate_id = import_candidate(candidate)
            store.update_legacy_state(
                candidate_id,
                state="active_legacy",
                baseline_candidate=1 if endpoint in baseline_endpoints else 0,
                assigned_country=country or None,
                legacy_country=country or None,
                last_decision_status="legacy",
                published=1,
                last_published_at=migration_timestamp,
            )

        counts = store.counts()
        store.set_metadata("migration_counts", counts)
        store.set_metadata("migration_finished_at", now_iso())

        baseline_rows = store.rows("s.baseline_candidate=1")
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        with baseline_path.open("w", encoding="utf-8-sig", newline="") as handle:
            fieldnames = [
                "candidate_id", "fingerprint", "endpoint", "host", "port", "source", "state",
                "legacy_country", "legacy_geo_evidence", "baseline_reasons", "raw_line",
            ]
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in sorted(baseline_rows, key=lambda item: str(item["endpoint"])):
                endpoint_key = str(row["endpoint"]).lower()
                pool = next((item for item in pool_rows if str(item.get("endpoint") or "").lower() == endpoint_key), {})
                verify = verify_by_endpoint.get(endpoint_key, {})
                writer.writerow(
                    {
                        "candidate_id": row["candidate_id"],
                        "fingerprint": row["fingerprint"],
                        "endpoint": row["endpoint"],
                        "host": row["host"],
                        "port": row["port"],
                        "source": row["source"],
                        "state": row["state"],
                        "legacy_country": row["legacy_country"] or "",
                        "legacy_geo_evidence": verify.get("geo_evidence") or pool.get("geo_evidence") or "",
                        "baseline_reasons": "|".join(sorted(baseline_reasons.get(endpoint_key, set()))),
                        "raw_line": row["raw_line"],
                    }
                )

    summary = {
        "database": str(db_path),
        "pool_input_count": len(pool_rows),
        "final_verify_input_count": len(verify_rows),
        "published_input_count": len(published),
        "baseline_candidate_count": len(baseline_endpoints),
        "database_counts": counts,
        "baseline_output": str(baseline_path),
    }
    summary_path = workdir / "migration_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
