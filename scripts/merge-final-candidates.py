import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bestcf_tool as tool


def read_candidate_lines(path: Path, required: bool) -> tuple[list[tuple[tuple[str, int], str]], int]:
    if not path.exists():
        if required:
            raise FileNotFoundError(path)
        return [], 0

    rows: list[tuple[tuple[str, int], str]] = []
    invalid = 0
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        base = line.split("|", 1)[0].strip()
        candidate = tool.parse_candidate(path.stem, base)
        if candidate is None or "#" not in base:
            invalid += 1
            continue
        rows.append((candidate.key, base))
    return rows, invalid


def merge_candidate_files(primary: Path, supplements: list[Path], output: Path) -> dict[str, Any]:
    primary_rows, primary_invalid = read_candidate_lines(primary, required=True)
    merged: dict[tuple[str, int], str] = {}
    duplicate_count = 0
    for key, line in primary_rows:
        if key in merged:
            duplicate_count += 1
            continue
        merged[key] = line

    supplement_reports: list[dict[str, Any]] = []
    supplement_added = 0
    for path in supplements:
        rows, invalid = read_candidate_lines(path, required=False)
        added = 0
        duplicates = 0
        for key, line in rows:
            if key in merged:
                duplicates += 1
                continue
            merged[key] = line
            added += 1
        supplement_added += added
        duplicate_count += duplicates
        supplement_reports.append(
            {
                "path": str(path),
                "exists": path.exists(),
                "candidate_count": len(rows),
                "added_count": added,
                "duplicate_count": duplicates,
                "invalid_count": invalid,
            }
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output.with_suffix(output.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
        for line in merged.values():
            handle.write(line + "\n")
    os.replace(temp_path, output)

    return {
        "primary": str(primary),
        "output": str(output),
        "primary_candidate_count": len(primary_rows),
        "primary_invalid_count": primary_invalid,
        "supplement_added_count": supplement_added,
        "duplicate_count": duplicate_count,
        "output_count": len(merged),
        "supplements": supplement_reports,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge current source candidates into the primary final candidate list.")
    parser.add_argument("--primary", required=True)
    parser.add_argument("--supplement", action="append", default=[])
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-json", default=None)
    args = parser.parse_args()

    summary = merge_candidate_files(
        Path(args.primary),
        [Path(value) for value in args.supplement],
        Path(args.output),
    )
    if args.summary_json:
        summary_path = Path(args.summary_json)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
