import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bestcf_tool as tool


def parse_named_path(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise ValueError(f"expected LINE=PATH, got {value!r}")
    line_id, path = value.split("=", 1)
    line_id = line_id.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", line_id):
        raise ValueError(f"invalid line id: {line_id!r}")
    if not path.strip():
        raise ValueError(f"empty path for line {line_id}")
    return line_id, Path(path)


def parse_aliases(value: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for item in str(value or "").split(","):
        item = item.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError(f"invalid country alias: {item}")
        source, target = (part.strip().upper() for part in item.split(":", 1))
        if not re.fullmatch(r"[A-Z]{2}", source) or not re.fullmatch(r"[A-Z]{2}", target):
            raise ValueError(f"invalid country alias: {item}")
        aliases[source] = target
    return aliases


def read_verified_file(line_id: str, path: Path, aliases: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        raw = line.strip()
        if not raw:
            continue
        base = raw.split("|", 1)[0]
        if "#" not in base:
            raise ValueError(f"{path}:{line_no}: missing country label")
        endpoint, label = base.rsplit("#", 1)
        candidate = tool.parse_candidate(f"line_{line_id}", f"{endpoint}#{label}")
        if candidate is None:
            raise ValueError(f"{path}:{line_no}: invalid endpoint")
        country = (tool.country_code_from_text(re.sub(r"-\d+$", "", label)) or "UNKNOWN").upper()
        country = aliases.get(country, country)
        if country == "UNKNOWN":
            continue
        rows.append(
            {
                "line_id": line_id,
                "candidate": candidate,
                "country": country,
                "raw_line": raw,
            }
        )
    return rows


def read_pool_latencies(specs: list[str]) -> dict[tuple[str, tuple[str, int]], float]:
    latencies: dict[tuple[str, tuple[str, int]], float] = {}
    for spec in specs:
        line_id, path = parse_named_path(spec)
        if not path.exists():
            raise FileNotFoundError(path)
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                candidate = tool.parse_candidate("pool_latency", str(row.get("endpoint") or ""))
                if candidate is None:
                    continue
                value = row.get("proxy_latency_p90_ms") or row.get("proxy_latency_ms")
                try:
                    latency = float(str(value))
                except (TypeError, ValueError):
                    continue
                latencies[(line_id, candidate.key)] = latency
    return latencies


def merge_observations(
    observations: list[dict[str, Any]],
    latency_by_line_key: dict[tuple[str, tuple[str, int]], float],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        grouped[observation["candidate"].key].append(observation)

    merged: list[dict[str, Any]] = []
    for key, items in grouped.items():
        by_line: dict[str, dict[str, Any]] = {}
        for item in items:
            by_line[item["line_id"]] = item
        unique_items = list(by_line.values())
        votes = Counter(item["country"] for item in unique_items)
        country = sorted(votes, key=lambda code: (-votes[code], code))[0]
        candidate = unique_items[0]["candidate"]
        line_ids = sorted(by_line)
        latency_values = [
            latency_by_line_key[(line_id, key)]
            for line_id in line_ids
            if (line_id, key) in latency_by_line_key
        ]
        merged.append(
            {
                "candidate": candidate,
                "country": country,
                "passed_lines": line_ids,
                "passed_line_count": len(line_ids),
                "country_votes": dict(sorted(votes.items())),
                "worst_p90_latency_ms": max(latency_values) if latency_values else None,
            }
        )
    merged.sort(
        key=lambda row: (
            -int(row["passed_line_count"]),
            row["worst_p90_latency_ms"] is None,
            row["worst_p90_latency_ms"] if row["worst_p90_latency_ms"] is not None else float("inf"),
            row["candidate"].endpoint,
        )
    )
    return merged


def select_merged(
    rows: list[dict[str, Any]],
    country_max: int,
    overrides: dict[str, int],
    host_max_ports: int,
    max_final: int,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    selected_keys: set[tuple[str, int]] = set()
    country_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    host_limits = (host_max_ports,) if host_max_ports > 0 else (1, 2, 6)
    for host_limit in host_limits:
        for row in rows:
            key = row["candidate"].key
            if key in selected_keys:
                continue
            country = str(row["country"])
            host = row["candidate"].host.lower()
            limit = overrides.get(country, country_max)
            if limit > 0 and country_counts[country] >= limit:
                continue
            if host_counts[host] >= host_limit:
                continue
            selected.append(row)
            selected_keys.add(key)
            country_counts[country] += 1
            host_counts[host] += 1
            if max_final > 0 and len(selected) >= max_final:
                return selected
    return selected


def write_output(path: Path, rows: list[dict[str, Any]]) -> None:
    counters: Counter[str] = Counter()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            region = tool.country_name(row["country"])
            counters[region] += 1
            handle.write(f"{row['candidate'].endpoint}#{region}-{counters[region]}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge independently verified CN-line outputs into a ranked union.")
    parser.add_argument("--input", action="append", required=True, help="verified line input as LINE=PATH; repeatable")
    parser.add_argument("--pool", action="append", default=[], help="optional pool CSV as LINE=PATH for P90 ranking")
    parser.add_argument("--output", required=True)
    parser.add_argument("--details-csv", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--country-max", type=int, default=30)
    parser.add_argument("--country-max-overrides", default="HK:20,DE:20")
    parser.add_argument("--country-aliases", default="VN:HK")
    parser.add_argument(
        "--host-max-ports",
        type=int,
        default=0,
        help="hard host cap; 0 uses the stateful soft sequence 1,2,6",
    )
    parser.add_argument("--max-final-candidates", type=int, default=0)
    parser.add_argument("--min-lines", type=int, default=10)
    parser.add_argument("--min-regions", type=int, default=3)
    args = parser.parse_args()

    aliases = parse_aliases(args.country_aliases)
    observations: list[dict[str, Any]] = []
    input_counts: dict[str, int] = {}
    for spec in args.input:
        line_id, path = parse_named_path(spec)
        if not path.exists():
            raise FileNotFoundError(path)
        rows = read_verified_file(line_id, path, aliases)
        observations.extend(rows)
        input_counts[line_id] = len(rows)

    latency_by_line_key = read_pool_latencies(args.pool)
    merged = merge_observations(observations, latency_by_line_key)
    overrides = tool.parse_country_min(args.country_max_overrides)
    selected = select_merged(
        merged,
        country_max=max(0, args.country_max),
        overrides=overrides,
        host_max_ports=max(0, args.host_max_ports),
        max_final=max(0, args.max_final_candidates),
    )
    output_path = Path(args.output)
    write_output(output_path, selected)
    ok, validation = tool.validate_final_output(
        output_path,
        min_lines=max(1, args.min_lines),
        min_regions=max(1, args.min_regions),
    )
    if not ok:
        raise SystemExit(validation)

    selected_keys = {row["candidate"].key for row in selected}
    details_path = Path(args.details_csv)
    details_path.parent.mkdir(parents=True, exist_ok=True)
    with details_path.open("w", encoding="utf-8-sig", newline="") as handle:
        fieldnames = [
            "endpoint",
            "host",
            "port",
            "selected_country",
            "passed_line_count",
            "passed_lines",
            "country_votes",
            "worst_p90_latency_ms",
            "selected_in_output",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in merged:
            candidate = row["candidate"]
            writer.writerow(
                {
                    "endpoint": candidate.endpoint,
                    "host": candidate.host,
                    "port": candidate.port,
                    "selected_country": row["country"],
                    "passed_line_count": row["passed_line_count"],
                    "passed_lines": "|".join(row["passed_lines"]),
                    "country_votes": "|".join(f"{key}:{value}" for key, value in row["country_votes"].items()),
                    "worst_p90_latency_ms": row["worst_p90_latency_ms"] if row["worst_p90_latency_ms"] is not None else "",
                    "selected_in_output": candidate.key in selected_keys,
                }
            )

    summary = {
        "inputs": input_counts,
        "input_observations": len(observations),
        "unique_candidates": len(merged),
        "selected_count": len(selected),
        "country_max": max(0, args.country_max),
        "country_max_overrides": overrides,
        "country_aliases": aliases,
        "host_max_ports": max(0, args.host_max_ports),
        "host_selection": "soft:1,2,6" if args.host_max_ports <= 0 else f"hard:{args.host_max_ports}",
        "selected_by_country": dict(sorted(Counter(row["country"] for row in selected).items())),
        "selected_by_passed_line_count": dict(
            sorted(Counter(str(row["passed_line_count"]) for row in selected).items())
        ),
        "validation": validation,
    }
    Path(args.summary_json).write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
