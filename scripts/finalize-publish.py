#!/usr/bin/env python3
"""Commit a staged publication to SQLite after the online SHA-256 check succeeds."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import geo_policy
import scheduler
from state_store import StateStore


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("publish manifest must be a JSON object")
    return value


def validate_manifest(store: StateStore, manifest: dict[str, Any], artifact_path: Path) -> list[tuple[int, str, str, int]]:
    if int(manifest.get("manifest_version") or 0) != 1:
        raise ValueError("unsupported publish manifest version")
    if str(manifest.get("policy_version") or "") != geo_policy.POLICY_VERSION:
        raise ValueError("publish manifest policy version is not the strict YouTube/Ping0 policy")
    run_id = int(manifest.get("run_id") or 0)
    if run_id <= 0:
        raise ValueError("publish manifest has no valid run_id")
    expected_sha = str(manifest.get("artifact_sha256") or "").upper()
    actual_sha = sha256_file(artifact_path)
    if not expected_sha or actual_sha != expected_sha:
        raise ValueError(f"artifact SHA-256 mismatch: expected={expected_sha} actual={actual_sha}")

    selected = manifest.get("selected")
    if not isinstance(selected, list) or not selected:
        raise ValueError("publish manifest selected list is empty")
    effective_mode = str(manifest.get("effective_mode") or "")
    if effective_mode not in {"wednesday", "sunday"}:
        raise ValueError("publish manifest effective_mode is invalid")

    selections: list[tuple[int, str, str, int]] = []
    expected_lines: list[str] = []
    seen_ids: set[int] = set()
    seen_endpoints: set[str] = set()
    for item in selected:
        if not isinstance(item, dict):
            raise ValueError("publish manifest contains a non-object selection")
        candidate_id = int(item.get("candidate_id") or 0)
        endpoint = str(item.get("endpoint") or "")
        fingerprint = str(item.get("fingerprint") or "")
        country = str(item.get("country") or "").upper()
        label = str(item.get("label") or "")
        rank = int(item.get("rank") or 0)
        if candidate_id <= 0 or not endpoint or not fingerprint or not country or not label or rank <= 0:
            raise ValueError(f"invalid manifest selection: {item}")
        if candidate_id in seen_ids or endpoint.lower() in seen_endpoints:
            raise ValueError(f"duplicate manifest selection: {candidate_id} {endpoint}")
        seen_ids.add(candidate_id)
        seen_endpoints.add(endpoint.lower())

        row = store.connection.execute(
            "SELECT c.*,s.* FROM candidates c JOIN candidate_state s USING(candidate_id) WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"manifest candidate does not exist: {candidate_id}")
        if str(row["fingerprint"]) != fingerprint or str(row["endpoint"]).lower() != endpoint.lower():
            raise ValueError(f"manifest candidate identity changed: {candidate_id}")
        if str(row["assigned_country"] or "").upper() != country:
            raise ValueError(f"manifest candidate country changed: {candidate_id}")
        if not scheduler.is_publishable(row):
            raise ValueError(f"manifest candidate is no longer publishable: {candidate_id}")
        if int(row["latency_sample_count"] or 0) < 3:
            raise ValueError(f"manifest candidate lacks three-sample latency verification: {candidate_id}")
        if country != "HK" or effective_mode == "sunday" or not bool(row["published"]):
            if int(row["last_run_id"] or 0) != run_id:
                raise ValueError(f"manifest candidate was not verified in staged run: {candidate_id}")
        expected_lines.append(f"{endpoint}#{label}-{rank}")
        selections.append((candidate_id, country, label, rank))

    actual_lines = [line.strip() for line in artifact_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if actual_lines != expected_lines:
        raise ValueError("artifact lines do not exactly match publish manifest order")
    return selections


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="bestcf_work/bestcf_observations.sqlite")
    parser.add_argument("--manifest", default="bestcf_work/staging/publish_manifest.json")
    parser.add_argument("--artifact", default="bestcf_work/staging/bestcf_final.txt")
    parser.add_argument("--result-json", default="bestcf_work/staging/finalize_result.json")
    args = parser.parse_args()

    db_path = Path(args.db)
    manifest_path = Path(args.manifest)
    artifact_path = Path(args.artifact)
    if not db_path.exists() or not manifest_path.exists() or not artifact_path.exists():
        raise SystemExit("database, manifest, and artifact must all exist before finalization")

    manifest = load_manifest(manifest_path)
    run_id = int(manifest.get("run_id") or 0)
    artifact_sha = str(manifest.get("artifact_sha256") or "").upper()
    with StateStore(db_path) as store:
        selections = validate_manifest(store, manifest, artifact_path)
        already_finalized = store.publish_already_finalized(run_id, artifact_sha)
        store.finalize_publish(
            run_id=run_id,
            selections=selections,
            artifact_sha256=artifact_sha,
        )

    result = {
        "ok": True,
        "already_finalized": already_finalized,
        "run_id": run_id,
        "artifact_sha256": artifact_sha,
        "published_count": len(selections),
    }
    output = Path(args.result_json)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
