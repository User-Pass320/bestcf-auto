import argparse
import csv
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bestcf_tool as tool


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify final.txt labels against live true exits and rewrite labels from live results.")
    parser.add_argument("--input", required=True, help="candidate final.txt path")
    parser.add_argument("--output", required=True, help="verified final.txt output path")
    parser.add_argument("--workdir", required=True, help="verification work directory")
    parser.add_argument("--template", required=True, help="mihomo template YAML")
    parser.add_argument("--mihomo", required=True, help="mihomo executable")
    parser.add_argument("--providers", default="youtube,ping0,ipwhois", help="geo providers")
    parser.add_argument("--geo-concurrency", type=int, default=16)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--start-timeout", type=float, default=8.0)
    parser.add_argument("--base-port", type=int, default=52100)
    parser.add_argument("--controller-base-port", type=int, default=53100)
    parser.add_argument("--details-csv", default=None)
    parser.add_argument("--summary-json", default=None)
    parser.add_argument("--min-lines", type=int, default=30)
    parser.add_argument("--min-regions", type=int, default=3)
    args_ns = parser.parse_args()

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
        geo_providers_resolved=tool.parse_geo_providers(args_ns.providers),
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

    meta_by_key = {row["candidate"].key: row for row in rows}
    result_by_key = {result.candidate.key: result for result in results}
    detail_rows: list[dict[str, Any]] = []
    verified_results: list[tool.TestResult] = []
    for row in rows:
        result = result_by_key.get(row["candidate"].key)
        actual = ((result.exit_country_code if result else "") or "UNKNOWN").upper()
        expected = row["expected_country"]
        comparable = expected != "UNKNOWN"
        consistent = comparable and actual == expected
        if result and result.exit_country_code:
            verified_results.append(result)
        detail_rows.append(
            {
                "line_no": row["line_no"],
                "endpoint": row["endpoint"],
                "label": row["label"],
                "expected_country": expected,
                "actual_country": actual,
                "input_consistent": consistent,
                "input_comparable": comparable,
                "status": result.status if result else "missing_result",
                "error": result.error if result else "result missing",
                "exit_region": result.exit_region if result else "未知",
                "exit_ip": result.exit_ip or "" if result else "",
                "cf_colo": result.cf_colo or "" if result else "",
                "geo_selected_provider": result.geo_selected_provider if result else "",
                "geo_fallback_used": result.geo_fallback_used if result else "",
                "geo_evidence": result.geo_evidence if result else "",
                "raw_line": row["raw_line"],
            }
        )

    unknown_rows = [row for row in detail_rows if row["actual_country"] == "UNKNOWN"]
    if unknown_rows:
        sample = ", ".join(f"{row['line_no']}:{row['endpoint']}" for row in unknown_rows[:10])
        raise SystemExit(f"true-exit verification failed: unknown actual exits={len(unknown_rows)} sample={sample}")

    write_verified_final(output_path, verified_results)
    ok, message = tool.validate_final_output(output_path, min_lines=args_ns.min_lines, min_regions=args_ns.min_regions)
    if not ok:
        raise SystemExit(message)

    if args_ns.details_csv:
        details_path = Path(args_ns.details_csv)
        details_path.parent.mkdir(parents=True, exist_ok=True)
        with details_path.open("w", encoding="utf-8-sig", newline="") as handle:
            fieldnames = [
                "line_no",
                "endpoint",
                "label",
                "expected_country",
                "actual_country",
                "input_consistent",
                "input_comparable",
                "status",
                "error",
                "exit_region",
                "exit_ip",
                "cf_colo",
                "geo_selected_provider",
                "geo_fallback_used",
                "geo_evidence",
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
        "elapsed_seconds": round(elapsed, 3),
        "input_count": len(rows),
        "output_count": len(verified_results),
        "input_comparable_count": len(input_comparable),
        "input_consistent_count": len(input_comparable) - len(input_mismatch),
        "input_mismatch_count": len(input_mismatch),
        "unknown_actual_count": len(unknown_rows),
        "input_by_expected_country": dict(sorted(Counter(row["expected_country"] for row in detail_rows).items())),
        "output_by_actual_country": dict(sorted(Counter(row["actual_country"] for row in detail_rows).items())),
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
