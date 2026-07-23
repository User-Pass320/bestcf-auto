import argparse
import csv
import dataclasses
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bestcf_tool as tool


def parse_country_aliases(text: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for part in str(text or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"invalid country alias: {part}")
        src, dst = part.split(":", 1)
        src = src.strip().upper()
        dst = dst.strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", src) or not re.fullmatch(r"[A-Z]{2}", dst):
            raise ValueError(f"invalid country alias: {part}")
        aliases[src] = dst
    return aliases


def normalize_country_code(code: str | None, aliases: dict[str, str]) -> str:
    normalized = (code or "UNKNOWN").upper()
    return aliases.get(normalized, normalized)


def parse_expected_country(label: str) -> str:
    value = re.sub(r"-\d+$", "", label.strip())
    if re.fullmatch(r"[A-Za-z]{2}", value):
        return value.upper()
    return (tool.country_code_from_text(value) or "UNKNOWN").upper()


def read_final_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        raw = line.strip()
        if not raw:
            continue
        base = raw.split("|", 1)[0].strip()
        if "#" not in base:
            raise ValueError(f"line {line_no}: missing label: {raw}")
        endpoint, label = base.rsplit("#", 1)
        candidate = tool.parse_candidate("final_verify", f"{endpoint}#{label}")
        if candidate is None:
            raise ValueError(f"line {line_no}: invalid endpoint: {raw}")
        rows.append(
            {
                "line_no": line_no,
                "candidate": candidate,
                "endpoint": candidate.endpoint,
                "label": re.sub(r"-\d+$", "", label.strip()),
                "expected_country": parse_expected_country(label),
                "raw_line": raw,
            }
        )
    return rows


def write_verified_final(path: Path, results: list[tool.TestResult]) -> None:
    counters: Counter[str] = Counter()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for result in results:
            if not result.exit_country_code:
                continue
            region = tool.country_name(result.exit_country_code)
            counters[region] += 1
            handle.write(f"{result.candidate.endpoint}#{region}-{counters[region]}\n")


def select_verified_results(
    results: list[tool.TestResult],
    country_max: int,
    country_max_overrides: dict[str, int],
    max_final_candidates: int,
    host_max_ports: int = 0,
    exit_ip_max: int = 0,
) -> list[tool.TestResult]:
    selected: list[tool.TestResult] = []
    counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    exit_ip_counts: Counter[str] = Counter()
    for result in results:
        code = (result.exit_country_code or "").upper()
        if not code:
            continue
        host = result.candidate.host.lower()
        exit_ip = str(result.exit_ip or "").strip().lower()
        limit = country_max_overrides.get(code, country_max)
        if limit > 0 and counts[code] >= limit:
            continue
        if host_max_ports > 0 and host_counts[host] >= host_max_ports:
            continue
        if exit_ip and exit_ip_max > 0 and exit_ip_counts[exit_ip] >= exit_ip_max:
            continue
        selected.append(result)
        counts[code] += 1
        host_counts[host] += 1
        if exit_ip:
            exit_ip_counts[exit_ip] += 1
        if max_final_candidates > 0 and len(selected) >= max_final_candidates:
            break
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify final.txt labels against live true exits and rewrite labels from live results.")
    parser.add_argument("--input", required=True, help="candidate final.txt path")
    parser.add_argument("--output", required=True, help="verified final.txt output path")
    parser.add_argument("--workdir", required=True, help="verification work directory")
    parser.add_argument("--template", required=True, help="mihomo template YAML")
    parser.add_argument("--mihomo", required=True, help="mihomo executable")
    parser.add_argument("--providers", default="youtube,ping0", help="diagnostic provider list; strict mode uses YouTube and Ping0 only")
    parser.add_argument(
        "--legacy-provider-vote",
        action="store_true",
        help="manual diagnostic compatibility only; automatic publishing must not use this option",
    )
    parser.add_argument("--geo-concurrency", type=int, default=16)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--start-timeout", type=float, default=8.0)
    parser.add_argument("--base-port", type=int, default=52100)
    parser.add_argument("--controller-base-port", type=int, default=53100)
    parser.add_argument("--details-csv", default=None)
    parser.add_argument("--summary-json", default=None)
    parser.add_argument("--region-counts-csv", default=None)
    parser.add_argument("--min-lines", type=int, default=30)
    parser.add_argument("--min-regions", type=int, default=3)
    parser.add_argument("--country-max", type=int, default=0, help="maximum verified output nodes per actual country; 0 disables")
    parser.add_argument("--country-max-overrides", default="", help="per-country verified output cap, e.g. HK:20,DE:20")
    parser.add_argument("--actual-country-aliases", default="", help="normalize live actual countries before labeling/capping, e.g. VN:HK")
    parser.add_argument(
        "--drop-unknown",
        action="store_true",
        help="exclude candidates whose live exit country cannot be resolved instead of failing verification",
    )
    parser.add_argument("--max-final-candidates", type=int, default=0, help="maximum verified output nodes; 0 disables")
    parser.add_argument("--host-max-ports", type=int, default=0, help="maximum selected ports per front host; 0 disables")
    parser.add_argument("--exit-ip-max", type=int, default=0, help="maximum selected nodes per live true-exit IP; 0 disables")
    args_ns = parser.parse_args()
    actual_country_aliases = parse_country_aliases(args_ns.actual_country_aliases)

    input_path = Path(args_ns.input)
    output_path = Path(args_ns.output)
    workdir = Path(args_ns.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    for dirname in ["geo_workers", "logs"]:
        (workdir / dirname).mkdir(parents=True, exist_ok=True)

    rows = read_final_rows(input_path)
    if not rows:
        raise SystemExit(f"no final rows: {input_path}")

    runtime_args = argparse.Namespace(
        workdir=str(workdir),
        mihomo=str(Path(args_ns.mihomo)),
        template=str(Path(args_ns.template)),
        template_name=None,
        base_port=int(args_ns.base_port),
        controller_base_port=int(args_ns.controller_base_port),
        start_timeout=float(args_ns.start_timeout),
        timeout=int(args_ns.timeout),
        geo_concurrency=max(1, int(args_ns.geo_concurrency)),
        geo_providers_resolved=(
            tool.parse_geo_providers(args_ns.providers)
            if args_ns.legacy_provider_vote
            else ["youtube", "ping0"]
        ),
        geo_policy="auto" if args_ns.legacy_provider_vote else "youtube-ping0-strict",
        geo_cache_enabled=False,
        geo_cache={"version": tool.GEO_CACHE_VERSION, "entries": {}},
        geo_cache_ttl_hours=0,
        geo_cache_lock=None,
        geo_hint_cache_enabled=False,
        geo_hint_cache=tool.empty_geo_hint_cache(),
        geo_hint_cache_lock=None,
        geo_hint_min_count=1,
        geo_hint_min_confidence=0.67,
        allow_other_regions=True,
        preferred_countries=set(),
        allow_unknown_region=False,
        service_check=False,
        min_service_score=0,
        google_url=tool.DEFAULT_SERVICE_URLS["google"],
        youtube_url=tool.DEFAULT_SERVICE_URLS["youtube"],
        gpt_url=tool.DEFAULT_SERVICE_URLS["gpt"],
        verbose_services=False,
        service_timeout=5,
        selection_mode="all-regions",
        hk_suppression=False,
        hk_suppress_strategy="worker",
        timings={},
    )

    template_proxy = tool.load_template(Path(runtime_args.template), template_name=None)
    geo_items = [(f"line-{row['line_no']}", row["candidate"], 0) for row in rows]
    started = time.time()
    results = tool.run_geo_batch(geo_items, template_proxy, runtime_args, "final_true_exit_verify")
    elapsed = time.time() - started

    result_by_key = {result.candidate.key: result for result in results}
    candidate_key_by_line_no = {int(row["line_no"]): row["candidate"].key for row in rows}
    detail_rows: list[dict[str, Any]] = []
    verified_results: list[tool.TestResult] = []
    for row in rows:
        result = result_by_key.get(row["candidate"].key)
        raw_actual = ((result.exit_country_code if result else "") or "UNKNOWN").upper()
        actual = normalize_country_code(raw_actual, actual_country_aliases)
        raw_expected = row["expected_country"]
        expected = normalize_country_code(raw_expected, actual_country_aliases)
        comparable = expected != "UNKNOWN"
        consistent = comparable and actual == expected
        if result and result.exit_country_code:
            verified_results.append(
                dataclasses.replace(
                    result,
                    exit_country_code=actual,
                    exit_region=tool.country_name(actual),
                    geo_evidence=(
                        f"{result.geo_evidence};alias:{raw_actual}->{actual}"
                        if raw_actual != actual and result.geo_evidence
                        else (f"alias:{raw_actual}->{actual}" if raw_actual != actual else result.geo_evidence)
                    ),
                )
            )
        detail_rows.append(
            {
                "line_no": row["line_no"],
                "endpoint": row["endpoint"],
                "label": row["label"],
                "raw_expected_country": raw_expected,
                "expected_country": expected,
                "raw_actual_country": raw_actual,
                "actual_country": actual,
                "actual_country_alias_applied": raw_actual != actual,
                "input_consistent": consistent,
                "input_comparable": comparable,
                "status": result.status if result else "missing_result",
                "error": result.error if result else "result missing",
                "exit_region": result.exit_region if result else "未知",
                "exit_ip": result.exit_ip or "" if result else "",
                "cf_colo": result.cf_colo or "" if result else "",
                "geo_selected_provider": result.geo_selected_provider if result else "",
                "geo_fallback_used": result.geo_fallback_used if result else "",
                "geo_decision_status": result.geo_decision_status if result else "",
                "geo_evidence": result.geo_evidence if result else "",
                "raw_line": row["raw_line"],
            }
        )

    unknown_rows = [row for row in detail_rows if row["actual_country"] == "UNKNOWN"]
    if unknown_rows and not args_ns.drop_unknown:
        sample = ", ".join(f"{row['line_no']}:{row['endpoint']}" for row in unknown_rows[:10])
        raise SystemExit(f"true-exit verification failed: unknown actual exits={len(unknown_rows)} sample={sample}")
    if unknown_rows:
        print(f"Dropping unresolved true exits: {len(unknown_rows)}", flush=True)

    country_max_overrides = tool.parse_country_min(args_ns.country_max_overrides)
    selected_results = select_verified_results(
        verified_results,
        country_max=max(0, int(args_ns.country_max)),
        country_max_overrides=country_max_overrides,
        max_final_candidates=max(0, int(args_ns.max_final_candidates)),
        host_max_ports=max(0, int(args_ns.host_max_ports)),
        exit_ip_max=max(0, int(args_ns.exit_ip_max)),
    )
    # Mark selection status without depending on endpoint uniqueness beyond the
    # already parsed candidate key map.
    selected_endpoint_keys = {result.candidate.key for result in selected_results}
    for row in detail_rows:
        candidate_key = candidate_key_by_line_no[int(row["line_no"])]
        row["selected_in_output"] = candidate_key in selected_endpoint_keys

    write_verified_final(output_path, selected_results)
    ok, message = tool.validate_final_output(output_path, min_lines=args_ns.min_lines, min_regions=args_ns.min_regions)
    if not ok:
        raise SystemExit(message)
    if args_ns.region_counts_csv:
        tool.write_region_counts(Path(args_ns.region_counts_csv), verified_results, selected_results)

    if args_ns.details_csv:
        details_path = Path(args_ns.details_csv)
        details_path.parent.mkdir(parents=True, exist_ok=True)
        with details_path.open("w", encoding="utf-8-sig", newline="") as handle:
            fieldnames = [
                "line_no",
                "endpoint",
                "label",
                "raw_expected_country",
                "expected_country",
                "raw_actual_country",
                "actual_country",
                "actual_country_alias_applied",
                "input_consistent",
                "input_comparable",
                "status",
                "error",
                "exit_region",
                "exit_ip",
                "cf_colo",
                "geo_selected_provider",
                "geo_fallback_used",
                "geo_decision_status",
                "geo_evidence",
                "selected_in_output",
                "raw_line",
            ]
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(detail_rows)

    input_comparable = [row for row in detail_rows if row["input_comparable"]]
    input_mismatch = [row for row in input_comparable if not row["input_consistent"]]
    summary = {
        "input": str(input_path),
        "output": str(output_path),
        "providers": runtime_args.geo_providers_resolved,
        "geo_policy": runtime_args.geo_policy,
        "elapsed_seconds": round(elapsed, 3),
        "input_count": len(rows),
        "output_count": len(selected_results),
        "input_comparable_count": len(input_comparable),
        "input_consistent_count": len(input_comparable) - len(input_mismatch),
        "input_mismatch_count": len(input_mismatch),
        "unknown_actual_count": len(unknown_rows),
        "verified_count": len(verified_results),
        "selected_count": len(selected_results),
        "dropped_by_post_verify_cap": len(verified_results) - len(selected_results),
        "country_max": max(0, int(args_ns.country_max)),
        "country_max_overrides": country_max_overrides,
        "actual_country_aliases": actual_country_aliases,
        "host_max_ports": max(0, int(args_ns.host_max_ports)),
        "exit_ip_max": max(0, int(args_ns.exit_ip_max)),
        "input_by_expected_country": dict(sorted(Counter(row["expected_country"] for row in detail_rows).items())),
        "verified_by_raw_actual_country": dict(sorted(Counter(row["raw_actual_country"] for row in detail_rows).items())),
        "verified_by_actual_country": dict(sorted(Counter(row["actual_country"] for row in detail_rows).items())),
        "output_by_actual_country": dict(sorted(Counter((result.exit_country_code or "UNKNOWN").upper() for result in selected_results).items())),
        "validation": message,
    }
    if args_ns.summary_json:
        summary_path = Path(args_ns.summary_json)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
