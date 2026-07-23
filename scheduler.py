"""Calendar and quota scheduler for stateful BestCF runs."""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
from collections import Counter
from collections.abc import Iterable
from typing import Any


NON_HK_CONFIRMED = "confirmed_non_hk"
HK_CONFIRMED = "confirmed_hk"


@dataclasses.dataclass(frozen=True, slots=True)
class PlannedCandidate:
    row: Any
    priority: int
    test_level: str
    reason: str


def stable_shard(value: str, count: int) -> int:
    if count <= 1:
        return 0
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % count


def cold_shard_index(day: dt.date, mode: str) -> int:
    anchor_week = dt.date(2026, 7, 20)
    current_week = day - dt.timedelta(days=day.weekday())
    week = (current_week - anchor_week).days // 7
    offset = 0 if mode == "wednesday" else 1
    return (week * 2 + offset) % 4


def cfst_port_group(day: dt.date) -> tuple[int, int]:
    groups = ((443, 2053), (2083, 2087), (2096, 8443))
    anchor_week = dt.date(2026, 7, 6)  # Monday; 443/2053 anchor group.
    current_week = day - dt.timedelta(days=day.weekday())
    elapsed_weeks = (current_week - anchor_week).days // 7
    return groups[elapsed_weeks % len(groups)]


def _country(row: Any) -> str:
    return str(row["assigned_country"] or row["legacy_country"] or "").upper()


def is_due(row: Any, day: dt.date) -> bool:
    try:
        value = str(row["next_test_at"] or "").strip()
    except (IndexError, KeyError):
        return True
    if not value or value.lower() == "next":
        return True
    try:
        return dt.datetime.fromisoformat(value).date() <= day
    except ValueError:
        return True


def _add(
    plan: dict[int, PlannedCandidate],
    row: Any,
    priority: int,
    test_level: str,
    reason: str,
) -> None:
    candidate_id = int(row["candidate_id"])
    current = plan.get(candidate_id)
    candidate = PlannedCandidate(row, priority, test_level, reason)
    if current is None or (priority, 0 if test_level == "full" else 1) < (
        current.priority,
        0 if current.test_level == "full" else 1,
    ):
        plan[candidate_id] = candidate


def build_test_plan(
    rows: Iterable[Any],
    *,
    mode: str,
    day: dt.date | None = None,
    soft_limit: int = 600,
    hard_limit: int = 800,
    hk_archive_sample: int = 100,
) -> list[PlannedCandidate]:
    mode = mode.lower()
    current_day = day or dt.datetime.now().astimezone().date()
    all_rows = list(rows)
    if mode == "prebuild":
        return [
            PlannedCandidate(row, 0, "gate", "prebuild_non_hk_baseline")
            for row in sorted(all_rows, key=lambda item: item["fingerprint"])
            if int(row["baseline_candidate"] or 0) == 1
        ]
    if mode == "shadow":
        mode = "wednesday" if current_day.weekday() in {0, 1, 2, 3} else "sunday"
    if mode not in {"wednesday", "sunday", "manual"}:
        raise ValueError(f"unsupported run mode: {mode}")
    if mode == "manual":
        mode = "sunday"

    plan: dict[int, PlannedCandidate] = {}
    warm_shard = 0 if mode == "wednesday" else 1
    cold_shard = cold_shard_index(current_day, mode)
    hk_archive_rows: list[Any] = []

    for row in all_rows:
        state = str(row["state"] or "new")
        country = _country(row)
        fingerprint = str(row["fingerprint"])
        published = bool(row["published"])

        if published or state in {"active", "active_legacy"}:
            if country == "HK" and mode != "sunday":
                continue
            _add(plan, row, 0, "full", "active_country_refresh")
            continue

        if state in {"hot", "hot_legacy"}:
            if country == "HK" and mode != "sunday":
                continue
            if not is_due(row, current_day):
                continue
            _add(plan, row, 1, "light", "hot_standby_refresh")
            continue

        if state in {"new", "probation", "hk_suspect", "geo_mismatch", "geo_unknown"}:
            if is_due(row, current_day):
                _add(plan, row, 1, "light", state)
            continue

        if state in {"warm", "observed_once_legacy"}:
            if not is_due(row, current_day):
                continue
            if country == "HK":
                if mode == "sunday" and current_day.day <= 7:
                    _add(plan, row, 2, "light", "monthly_hk_warm")
            elif stable_shard(fingerprint, 2) == warm_shard:
                _add(plan, row, 2, "light", f"warm_shard_{warm_shard}")
            continue

        if state in {"cold", "cooldown", "cooldown_legacy", "failed_legacy", "archive", "archive_legacy"}:
            if not is_due(row, current_day):
                continue
            if country == "HK":
                if mode == "sunday":
                    hk_archive_rows.append(row)
            elif stable_shard(fingerprint, 4) == cold_shard:
                _add(plan, row, 2, "light", f"cold_shard_{cold_shard}")
            continue

    if mode == "sunday":
        hk_archive_rows.sort(
            key=lambda row: (
                0 if int(row["hk_seen_count"] or 0) == 0 else 1,
                str(row["last_tested_at"] or ""),
                str(row["fingerprint"]),
            )
        )
        for row in hk_archive_rows[: max(0, hk_archive_sample)]:
            _add(plan, row, 3, "light", "hk_archive_sample")

    ordered = sorted(
        plan.values(),
        key=lambda item: (
            item.priority,
            0 if item.test_level == "full" else 1,
            0 if bool(item.row["published"]) else 1,
            float(item.row["latency_median_ms"] or 10**9),
            str(item.row["fingerprint"]),
        ),
    )
    p0 = [item for item in ordered if item.priority == 0]
    if len(p0) > hard_limit:
        raise RuntimeError(f"active candidate count exceeds hard limit: {len(p0)} > {hard_limit}")
    selected: list[PlannedCandidate] = []
    for item in ordered:
        if len(selected) >= hard_limit:
            break
        if len(selected) >= soft_limit and item.priority >= 2:
            continue
        selected.append(item)
    return selected


def is_publishable(row: Any) -> bool:
    if str(row["state"] or "") not in {"hot", "active"}:
        return False
    country = str(row["assigned_country"] or "").upper()
    decision = str(row["last_decision_status"] or "")
    if not country:
        return False
    if country == "HK":
        return decision == HK_CONFIRMED and int(row["strict_success_count"] or 0) >= 1
    if decision != NON_HK_CONFIRMED:
        return False
    required = 3 if int(row["hk_seen_count"] or 0) > 0 else 2
    return int(row["country_success_streak"] or 0) >= required


def select_for_publish(
    rows: Iterable[Any],
    *,
    country_max: int = 30,
    country_overrides: dict[str, int] | None = None,
    exit_ip_max: int = 3,
) -> list[Any]:
    overrides = {key.upper(): int(value) for key, value in (country_overrides or {}).items()}
    candidates = [row for row in rows if is_publishable(row)]
    candidates.sort(
        key=lambda row: (
            0 if bool(row["published"]) else 1,
            float(row["latency_median_ms"] or 10**9),
            float(row["latency_p90_ms"] or 10**9),
            str(row["endpoint"]),
        )
    )
    selected: list[Any] = []
    selected_ids: set[int] = set()
    country_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    exit_counts: Counter[str] = Counter()

    for host_limit in (1, 2, 6):
        for row in candidates:
            candidate_id = int(row["candidate_id"])
            if candidate_id in selected_ids:
                continue
            country = str(row["assigned_country"] or "").upper()
            limit = overrides.get(country, country_max)
            if limit > 0 and country_counts[country] >= limit:
                continue
            host = str(row["host"] or "").lower()
            if host_counts[host] >= host_limit:
                continue
            exit_ip = str(row["canonical_exit_ip"] or "").lower()
            if exit_ip and exit_ip_max > 0 and exit_counts[exit_ip] >= exit_ip_max:
                continue
            selected.append(row)
            selected_ids.add(candidate_id)
            country_counts[country] += 1
            host_counts[host] += 1
            if exit_ip:
                exit_counts[exit_ip] += 1
    return selected
