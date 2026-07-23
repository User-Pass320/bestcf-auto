"""Strict true-exit policy used by the stateful SelfDeploy pipeline."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable


POLICY_VERSION = "youtube_ping0_strict_v1"
COUNTRY_ALIASES = {"VN": "HK"}


@dataclasses.dataclass(frozen=True, slots=True)
class ProbeObservation:
    provider: str
    country: str | None
    raw_country: str | None = None
    exit_ip: str | None = None
    colo: str | None = None
    attempt: int = 1
    status: str = "ok"
    error: str = ""


@dataclasses.dataclass(frozen=True, slots=True)
class StrictGeoDecision:
    status: str
    country: str | None
    exit_ip: str | None
    evidence: str
    youtube_country: str | None
    ping0_country: str | None

    @property
    def publishable(self) -> bool:
        return self.status in {"confirmed_non_hk", "confirmed_hk"} and bool(self.country)


def normalize_country(code: str | None, aliases: dict[str, str] | None = None) -> str | None:
    value = str(code or "").strip().upper()
    if not value or value in {"-", "UNKNOWN", "NONE", "NULL"}:
        return None
    return (aliases or COUNTRY_ALIASES).get(value, value)


def decide_strict(
    youtube_country: str | None,
    ping0_country: str | None,
    *,
    ping0_ip: str | None = None,
    evidence: str = "",
    aliases: dict[str, str] | None = None,
) -> StrictGeoDecision:
    youtube = normalize_country(youtube_country, aliases)
    ping0 = normalize_country(ping0_country, aliases)
    if youtube and ping0 and youtube == ping0:
        status = "confirmed_hk" if youtube == "HK" else "confirmed_non_hk"
        return StrictGeoDecision(status, youtube, ping0_ip, evidence, youtube, ping0)
    if "HK" in {youtube, ping0}:
        return StrictGeoDecision("hk_suspect", None, ping0_ip, evidence, youtube, ping0)
    if youtube and ping0:
        return StrictGeoDecision("geo_mismatch", None, ping0_ip, evidence, youtube, ping0)
    return StrictGeoDecision("geo_unknown", None, ping0_ip, evidence, youtube, ping0)


def decide_from_observations(
    observations: Iterable[ProbeObservation],
    *,
    aliases: dict[str, str] | None = None,
) -> StrictGeoDecision:
    rows = list(observations)
    latest: dict[str, ProbeObservation] = {}
    evidence_parts: list[str] = []
    for row in rows:
        provider = row.provider.strip().lower()
        if provider not in {"youtube", "ping0"}:
            continue
        latest[provider] = row
        suffix = "" if row.attempt <= 1 else f"_retry{row.attempt - 1}"
        raw_country = str(row.raw_country or row.country or "").strip().upper() or None
        evidence_parts.append(f"{provider}{suffix}:{raw_country or '-'}")
    youtube = latest.get("youtube")
    ping0 = latest.get("ping0")
    return decide_strict(
        (youtube.raw_country or youtube.country) if youtube else None,
        (ping0.raw_country or ping0.country) if ping0 else None,
        ping0_ip=ping0.exit_ip if ping0 else None,
        evidence=";".join(evidence_parts),
        aliases=aliases,
    )


def parse_evidence(evidence: str) -> list[ProbeObservation]:
    """Parse both legacy ``provider:CC`` evidence and strict retry evidence."""
    rows: list[ProbeObservation] = []
    for part in str(evidence or "").split(";"):
        if ":" not in part:
            continue
        raw_name, raw_country_value = part.split(":", 1)
        name = raw_name.strip().lower()
        attempt = 1
        if "_retry" in name:
            name, raw_attempt = name.rsplit("_retry", 1)
            try:
                attempt = max(2, int(raw_attempt) + 1)
            except ValueError:
                attempt = 2
        if name not in {"youtube", "ping0"}:
            continue
        raw_country = str(raw_country_value or "").strip().upper()
        if raw_country in {"", "-", "UNKNOWN", "NONE", "NULL"}:
            raw_country = ""
        country = normalize_country(raw_country)
        rows.append(
            ProbeObservation(
                provider=name,
                country=country,
                raw_country=raw_country or None,
                attempt=attempt,
                status="ok" if country else "unknown",
            )
        )
    return rows


def legacy_primary_hk_seen(evidence: str) -> bool:
    return any(row.country == "HK" for row in parse_evidence(evidence))
