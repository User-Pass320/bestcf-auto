#!/usr/bin/env python3
"""BestCF candidate rebinder and tester.

Downloads BestCF-style IP:port sources, rebinds candidates onto an existing
Mihomo/Clash proxy template, measures real proxied throughput, detects real
proxy egress region, and writes lines in this exact format:

    IP:port#region-rank|speedMB/s
"""

from __future__ import annotations

import argparse
import collections
import csv
import dataclasses
import ipaddress
import json
import os
import queue
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml


DEFAULT_SOURCES = {
    "uouin": "https://bestcf.pages.dev/uouin/all.txt",
    "wetest": "https://bestcf.pages.dev/wetest/ipv4.txt",
    "cfyes_ipv4": "https://bestcf.pages.dev/cfyes/ipv4.txt",
    "cfyes_ipv6": "https://bestcf.pages.dev/cfyes/ipv6.txt",
    "moistr": "https://bestcf.pages.dev/moistr/all.txt",
    "xinyitang3": "https://bestcf.pages.dev/xinyitang3/ipv4.txt",
    "luoli": "https://bestcf.pages.dev/luoli/all.txt",
    "gslege": "https://bestcf.pages.dev/gslege/Cfxyz.txt",
    "gslege_jp": "https://bestcf.pages.dev/gslege/JP.txt",
    "gslege_us": "https://bestcf.pages.dev/gslege/US.txt",
    "gslege_sg": "https://bestcf.pages.dev/gslege/SG.txt",
    "domain_all": "https://bestcf.pages.dev/domain/all.txt",
    "domain_mini": "https://bestcf.pages.dev/domain/mini.txt",
    "domain_asia": "https://bestcf.pages.dev/domain/Domain-Asia.txt",
    "domain_ai_vps789": "https://bestcf.pages.dev/domain/Domain-AI-VPS789.txt",
    "domain_ygkkk_all": "https://bestcf.pages.dev/domain/ygkkk/all.txt",
    "domain_qms_all": "https://bestcf.pages.dev/domain/qms/all.txt",
    "domain_fiatnorm_all": "https://bestcf.pages.dev/domain/fiatnorm/all.txt",
    "domain_senflare_all": "https://bestcf.pages.dev/domain/senflare/all.txt",
    "domain_wuya_all": "https://bestcf.pages.dev/domain/wuya/all.txt",
    "domain_ircf_all": "https://bestcf.pages.dev/domain/ircf/all.txt",
    "vps789_top100": "https://bestcf.pages.dev/vps789/top100.txt",
    "tiancheng2": "https://bestcf.pages.dev/tiancheng2/all.txt",
    "junzhen_bj": "https://cf.junzhen.qzz.io/best_ips_bj.txt",
    "love_ztm_best_ips": "https://raw.githubusercontent.com/love-ztm/cfip/refs/heads/main/best_ips.txt",
    "gshtwy_wetest_v4": "https://raw.githubusercontent.com/gshtwy/CF-DNS-Clone/refs/heads/main/wetest-cloudflare-v4.txt",
}

DEFAULT_TEMPLATE = Path(
    r"C:\Users\sundewang\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\clash-verge.yaml"
)
DEFAULT_MIHOMO = Path(r"E:\v2rayN-windows-64\bin\mihomo\mihomo.exe")
DEFAULT_WORKDIR = Path(r"C:\Users\sundewang\bestcf_work")
DEFAULT_SOURCE_CACHE_NAME = "bestcf_source_cache.json"
DEFAULT_GEO_CACHE_NAME = "bestcf_geo_cache.json"
DEFAULT_SOURCE_DENYLIST_NAME = "bestcf_source_denylist.txt"
DEFAULT_SOURCE_PRUNE_REPORT_NAME = "bestcf_source_prune_candidates.csv"
SOURCE_CACHE_VERSION = 1
GEO_CACHE_VERSION = 1
DEFAULT_SOURCE_INVALID_THRESHOLD = 2
DEFAULT_SOURCE_QUARANTINE_HOURS = 24.0
DEFAULT_SOURCE_PRUNE_MIN_LINES = 5
DEFAULT_SOURCE_HIGH_INVALID_RATIO = 0.90
DEFAULT_DISCOVERY_MIN_SOURCES = 20
DEFAULT_SERVICE_URLS = {
    "google": "https://www.gstatic.com/generate_204",
    "youtube": "https://www.youtube.com/generate_204",
    "gpt": "https://chatgpt.com/",
}
DEFAULT_LIGHT_SPEED_URLS = [
    "http://speedtest.tele2.net/10MB.zip",
]
DEFAULT_SPEED_URLS = [
    "https://speed.cloudflare.com/__down?bytes=25000000",
    "https://cachefly.cachefly.net/50mb.test",
    "https://speed.hetzner.de/10MB.bin",
    "http://speedtest.tele2.net/10MB.zip",
]

BESTCF_INDEX_URL = "https://bestcf.pages.dev/"
PREFERRED_COUNTRY_ORDER = ["JP", "SG", "US", "HK", "KR", "TW"]
PREFERRED_COUNTRY_CODES = set(PREFERRED_COUNTRY_ORDER)
PREFERRED_REGION_NAMES = {"香港", "日本", "新加坡", "美国", "韩国", "台湾"}
DEFAULT_LATENCY_URL = "https://www.gstatic.com/generate_204"
GEO_PROVIDER_URLS = {
    "ipinfo": "https://ipinfo.io/json",
    "ip_sb": "https://api.ip.sb/geoip",
    "cloudflare": "https://www.cloudflare.com/cdn-cgi/trace",
    "ping0": "https://ip.ping0.cc/geo",
    "ipapi": "https://ipapi.co/json/",
    "ipwhois": "https://ipwho.is/",
    "ip_api": "http://ip-api.com/json/?fields=status,countryCode,query",
}
DEFAULT_GEO_PROVIDERS_DAILY = ["ipwhois", "ping0", "cloudflare"]
DEFAULT_GEO_PROVIDERS_ALL = ["ipinfo", "ip_sb", "cloudflare", "ping0", "ipapi", "ipwhois", "ip_api"]
SOURCE_SKIP_MARKERS = (
    "/CIDR/",
    "/WARP/",
    "/subconfig/",
    "/random-region/",
    "Domain-Checked.txt",
    "Domain-TOP.txt",
    "client-ver.txt",
    "workers-date-card.txt",
)
BESTCF_SOURCE_PATH_ALLOW = (
    "/cfyes/",
    "/domain/",
    "/entryip/",
    "/gslege/",
    "/ircf/",
    "/luoli/",
    "/moistr/",
    "/nirevil/",
    "/tiancheng/",
    "/tiancheng2/",
    "/uouin/",
    "/vps789/",
    "/vvhan/",
    "/wetest/",
    "/xinyitang3/",
    "/zhixuanwang/",
)
EXTERNAL_SOURCE_ALLOW_HOSTS = {
    "cf.junzhen.qzz.io",
    "raw.githubusercontent.com",
}

COUNTRY_NAMES = {
    "HK": "香港",
    "JP": "日本",
    "SG": "新加坡",
    "US": "美国",
    "KR": "韩国",
    "TW": "台湾",
    "DE": "德国",
    "GB": "英国",
    "UK": "英国",
    "FR": "法国",
    "NL": "荷兰",
    "CA": "加拿大",
    "AU": "澳大利亚",
    "TH": "泰国",
    "VN": "越南",
    "MY": "马来西亚",
    "ID": "印度尼西亚",
    "PH": "菲律宾",
    "IN": "印度",
    "RS": "塞尔维亚",
}

REGION_ALIASES = {
    "HKG": "香港",
    "NRT": "日本",
    "KIX": "日本",
    "SIN": "新加坡",
    "SJC": "美国",
    "LAX": "美国",
    "SEA": "美国",
    "ICN": "韩国",
    "TPE": "台湾",
}

IP_PORT_RE = re.compile(r"^\s*(?P<host>\[[0-9a-fA-F:.]+\]|[^:#\s]+):(?P<port>\d{1,5})(?P<rest>#.*)?\s*$")
SPEED_RE = re.compile(r"(?P<speed>\d+(?:\.\d+)?)\s*(?:M|m)(?:B|b)/s")
LATENCY_RE = re.compile(r"(?P<latency>\d+(?:\.\d+)?)\s*ms", re.I)
ASCII_REGION_RE = re.compile(r"(?<![A-Z])([A-Z]{2,3})(?![A-Z])")

CLOUDFLARE_CIDRS = [
    "104.16.0.0/12",
    "108.162.0.0/16",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]
CF_NETWORKS = [ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_CIDRS]


@dataclasses.dataclass(slots=True)
class Candidate:
    source: str
    raw: str
    host: str
    port: int
    name: str = ""
    declared_speed: float | None = None
    declared_latency: float | None = None
    declared_region: str | None = None
    is_cloudflare: bool | None = None
    parse_format: str = "endpoint"
    port_inferred: bool = False

    @property
    def key(self) -> tuple[str, int]:
        return (self.host.lower(), self.port)

    @property
    def endpoint(self) -> str:
        return format_endpoint(self.host, self.port)


@dataclasses.dataclass(slots=True)
class TestResult:
    candidate: Candidate
    ok: bool
    status: str
    error: str = ""
    measured_speed: float | None = None
    latency_ms: float | None = None
    exit_ip: str | None = None
    exit_country_code: str | None = None
    exit_region: str = "未知"
    cf_colo: str | None = None
    geo_evidence: str = ""
    geo_cache_status: str = ""
    service_score: int = 0
    google_ok: bool | None = None
    youtube_ok: bool | None = None
    gpt_ok: bool | None = None
    service_error: str = ""
    selection_stage: str = ""


def format_endpoint(host: str, port: int) -> str:
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            return f"[{host}]:{port}"
    except ValueError:
        pass
    return f"{host}:{port}"


def country_name(code: str | None) -> str:
    if not code:
        return "未知"
    code = code.strip().upper()
    return COUNTRY_NAMES.get(code, code)


def country_rank(code: str | None, order: list[str]) -> int:
    if not code:
        return 999
    code = code.upper()
    try:
        return order.index(code)
    except ValueError:
        return 999


def country_code_from_text(text: str) -> str | None:
    upper = text.upper()
    for code in sorted(COUNTRY_NAMES, key=len, reverse=True):
        if re.search(rf"(?<![A-Z]){re.escape(code)}(?![A-Z])", upper):
            return code
    for code, name in sorted(COUNTRY_NAMES.items(), key=lambda item: len(item[1]), reverse=True):
        if name and name in text:
            return code
    for alias, name in REGION_ALIASES.items():
        if alias in upper or name in text:
            return next((code for code, country in COUNTRY_NAMES.items() if country == name), None)
    return None


def sort_geo_results(results: list[TestResult], order: list[str]) -> list[TestResult]:
    return sorted(
        results,
        key=lambda result: (
            country_rank(result.exit_country_code, order),
            result.latency_ms or 10**9,
            result.candidate.endpoint,
        ),
    )


def is_cloudflare_host(host: str) -> bool | None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    return any(ip in network for network in CF_NETWORKS)


def source_name_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    name = (parsed.netloc + parsed.path).strip("/").replace("/", "_").replace(".", "_").replace("-", "_")
    return re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_")[:80] or "source"


def normalize_source_url(raw: str, base_url: str = BESTCF_INDEX_URL) -> str | None:
    raw = raw.strip().strip("\"'<>")
    if not raw or "${" in raw:
        return None
    if not raw.endswith(".txt"):
        return None
    if raw.startswith("//"):
        raw = "https:" + raw
    elif raw.startswith("http://") or raw.startswith("https://"):
        pass
    elif raw.startswith("/bestcf.pages.dev/"):
        raw = "https://" + raw.lstrip("/")
    elif raw.startswith("bestcf.pages.dev/"):
        raw = "https://" + raw
    elif raw.startswith("cf.junzhen.qzz.io/") or raw.startswith("raw.githubusercontent.com/"):
        raw = "https://" + raw
    elif raw.startswith("/"):
        raw = urllib.parse.urljoin(base_url, raw)
    else:
        return None
    if any(marker.lower() in raw.lower() for marker in SOURCE_SKIP_MARKERS):
        return None
    parsed = urllib.parse.urlparse(raw)
    if parsed.netloc == "bestcf.pages.dev":
        if not any(marker.lower() in parsed.path.lower() for marker in BESTCF_SOURCE_PATH_ALLOW):
            return None
    elif parsed.netloc not in EXTERNAL_SOURCE_ALLOW_HOSTS:
        return None
    return raw


def discover_bestcf_sources(timeout: int) -> dict[str, str]:
    ok, html = fetch_url(BESTCF_INDEX_URL, timeout=timeout)
    if not ok:
        return {}
    found: dict[str, str] = {}
    patterns = [
        r"https?://[^\"'<>\\\s]+\.txt",
        r"(?<!:)//[^\"'<>\\\s]+\.txt",
        r"/[A-Za-z0-9_.${}-]+(?:/[A-Za-z0-9_.${}-]+)+\.txt",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, html):
            url = normalize_source_url(match.group(0))
            if not url:
                continue
            name = source_name_from_url(url)
            suffix = 2
            original = name
            while name in found and found[name] != url:
                name = f"{original}_{suffix}"
                suffix += 1
            found[name] = url
    return found


def cached_sources_from_cache(cache: dict[str, Any]) -> dict[str, str]:
    cache_sources = cache.get("sources") if isinstance(cache.get("sources"), dict) else {}
    found: dict[str, str] = {}
    for name, entry in cache_sources.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str):
            continue
        if normalize_source_url(url) != url:
            continue
        found[name] = url
    return found


def build_sources(discover: bool, timeout: int, source_cache: dict[str, Any] | None = None) -> dict[str, str]:
    sources = dict(DEFAULT_SOURCES)
    if not discover:
        return sources
    discovered = discover_bestcf_sources(timeout)
    cached = cached_sources_from_cache(source_cache) if source_cache else {}
    if cached and len(discovered) < DEFAULT_DISCOVERY_MIN_SOURCES:
        before = len(discovered)
        for name, url in cached.items():
            discovered.setdefault(name, url)
        print(
            "Source discovery fallback: "
            f"discovered={before}; cached_total={len(cached)}; merged={len(discovered)}",
            flush=True,
        )
    for name, url in discovered.items():
        if url in sources.values():
            continue
        sources[name] = url
    return sources


def load_source_denylist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    denied: set[str] = set()
    try:
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.split("#", 1)[0].strip()
                if line:
                    denied.add(line)
    except OSError:
        return set()
    return denied


def save_source_denylist(path: Path, denied: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# One source name or exact URL per line. Lines are removed before download.\n")
        for item in sorted(denied):
            handle.write(f"{item}\n")
    os.replace(tmp_path, path)


def filter_denied_sources(
    sources: dict[str, str],
    denied: set[str],
) -> tuple[dict[str, str], list[dict[str, str]]]:
    if not denied:
        return dict(sources), []
    active: dict[str, str] = {}
    skipped: list[dict[str, str]] = []
    for name, url in sources.items():
        if name in denied or url in denied:
            skipped.append(
                {
                    "source": name,
                    "url": url,
                    "status": "source_pruned_by_denylist",
                    "error": "source exists in hard denylist; removed before download",
                }
            )
            continue
        active[name] = url
    return active, skipped


def load_source_cache(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": SOURCE_CACHE_VERSION, "sources": {}}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {"version": SOURCE_CACHE_VERSION, "sources": {}}
    if not isinstance(data, dict):
        return {"version": SOURCE_CACHE_VERSION, "sources": {}}
    sources = data.get("sources")
    if not isinstance(sources, dict):
        sources = {}
    return {"version": SOURCE_CACHE_VERSION, "sources": sources}


def save_source_cache(path: Path, cache: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cache["version"] = SOURCE_CACHE_VERSION
    cache["updated_at"] = time.time()
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(cache, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_path, path)


def load_geo_cache(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": GEO_CACHE_VERSION, "entries": {}}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {"version": GEO_CACHE_VERSION, "entries": {}}
    if not isinstance(data, dict):
        return {"version": GEO_CACHE_VERSION, "entries": {}}
    entries = data.get("entries")
    if not isinstance(entries, dict):
        entries = {}
    return {"version": GEO_CACHE_VERSION, "entries": entries}


def save_geo_cache(path: Path, cache: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cache["version"] = GEO_CACHE_VERSION
    cache["updated_at"] = time.time()
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(cache, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_path, path)


def geo_cache_lookup(candidate: Candidate, args: argparse.Namespace, now: float) -> tuple[str, dict[str, Any] | None]:
    if not args.geo_cache_enabled:
        return "disabled", None
    entries = args.geo_cache.setdefault("entries", {})
    if not isinstance(entries, dict):
        args.geo_cache["entries"] = {}
        return "miss", None
    entry = entries.get(candidate.endpoint)
    if not isinstance(entry, dict):
        return "miss", None
    if float(entry.get("expires_at") or 0) <= now:
        return "expired", None
    if entry.get("providers") != args.geo_providers_resolved:
        return "provider_mismatch", None
    if not entry.get("exit_country_code"):
        return "miss", None
    return "hit", entry


def geo_cache_update(candidate: Candidate, result: TestResult, args: argparse.Namespace, now: float) -> None:
    if not args.geo_cache_enabled or not result.exit_country_code:
        return
    entry = {
        "endpoint": candidate.endpoint,
        "exit_ip": result.exit_ip or "",
        "exit_country_code": result.exit_country_code or "",
        "exit_region": result.exit_region,
        "cf_colo": result.cf_colo or "",
        "geo_evidence": result.geo_evidence,
        "providers": list(args.geo_providers_resolved),
        "checked_at": now,
        "expires_at": now + args.geo_cache_ttl_hours * 3600,
    }
    with args.geo_cache_lock:
        entries = args.geo_cache.setdefault("entries", {})
        if isinstance(entries, dict):
            entries[candidate.endpoint] = entry


def test_result_from_geo_cache(candidate: Candidate, delay: float, entry: dict[str, Any], cache_status: str) -> TestResult:
    code = str(entry.get("exit_country_code") or "").upper() or None
    return TestResult(
        candidate,
        True,
        "geo_cached",
        latency_ms=delay,
        exit_ip=str(entry.get("exit_ip") or "") or None,
        exit_country_code=code,
        exit_region=str(entry.get("exit_region") or country_name(code)),
        cf_colo=str(entry.get("cf_colo") or "") or None,
        geo_evidence=str(entry.get("geo_evidence") or ""),
        geo_cache_status=cache_status,
    )


def format_timestamp(timestamp: float | int | None) -> str:
    if not timestamp:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(timestamp)))
    except (OSError, OverflowError, ValueError):
        return ""


class StageTimer:
    def __init__(self) -> None:
        self.started_at = time.monotonic()
        self.last_at = self.started_at
        self.timings: dict[str, float] = {}

    def mark(self, name: str) -> None:
        now = time.monotonic()
        self.timings[name] = self.timings.get(name, 0.0) + (now - self.last_at)
        self.last_at = now

    def set(self, name: str, seconds: float) -> None:
        self.timings[name] = seconds

    def total(self) -> float:
        return time.monotonic() - self.started_at

    def summary(self) -> str:
        items = [f"{name}={seconds:.3f}s" for name, seconds in self.timings.items()]
        items.append(f"total={self.total():.3f}s")
        return "Timing: " + " ".join(items)


def filter_cached_invalid_sources(
    sources: dict[str, str],
    cache: dict[str, Any],
    refresh: bool,
) -> tuple[dict[str, str], list[dict[str, str]]]:
    if refresh:
        return dict(sources), []
    now = time.time()
    cache_sources = cache.get("sources") if isinstance(cache.get("sources"), dict) else {}
    active: dict[str, str] = {}
    skipped: list[dict[str, str]] = []
    for name, url in sources.items():
        entry = cache_sources.get(name)
        disabled_until = 0.0
        if isinstance(entry, dict) and entry.get("url") == url:
            try:
                disabled_until = float(entry.get("disabled_until") or 0)
            except (TypeError, ValueError):
                disabled_until = 0.0
        if disabled_until > now:
            skipped.append(
                {
                    "source": name,
                    "url": url,
                    "status": "source_skipped_cached_invalid",
                    "error": (
                        "cached invalid source; "
                        f"invalid_streak={entry.get('invalid_streak', '')}; "
                        f"disabled_until={format_timestamp(disabled_until)}"
                    ),
                }
            )
            continue
        active[name] = url
    return active, skipped


def empty_source_stat(source: str, url: str = "") -> dict[str, Any]:
    return {
        "source": source,
        "url": url,
        "raw_lines": 0,
        "nonempty_lines": 0,
        "valid_lines": 0,
        "invalid_lines": 0,
        "unique_selected": 0,
    }


def source_ratios(stat: dict[str, Any]) -> tuple[float, float]:
    nonempty = int(stat.get("nonempty_lines") or 0)
    if nonempty <= 0:
        return 0.0, 0.0
    valid = int(stat.get("valid_lines") or 0)
    invalid = int(stat.get("invalid_lines") or 0)
    return valid / nonempty, invalid / nonempty


def source_prune_action(
    stat: dict[str, Any],
    min_lines: int,
    high_invalid_ratio: float,
) -> tuple[str, str]:
    nonempty = int(stat.get("nonempty_lines") or 0)
    valid = int(stat.get("valid_lines") or 0)
    invalid = int(stat.get("invalid_lines") or 0)
    unique_selected = int(stat.get("unique_selected") or 0)
    valid_ratio, invalid_ratio = source_ratios(stat)
    min_lines = max(1, min_lines)
    if nonempty < min_lines:
        return "keep", f"sample_too_small nonempty={nonempty} min_lines={min_lines}"
    if valid == 0 and invalid > 0:
        return "auto_prune", "zero parseable candidates in nonempty source"
    if valid > 0 and invalid_ratio >= high_invalid_ratio:
        return (
            "review_high_invalid",
            f"has {valid} valid candidates; invalid_ratio={invalid_ratio:.6f}; not auto-pruned",
        )
    if valid > 0 and unique_selected == 0:
        return "review_redundant", "all parseable candidates were already covered by other sources"
    if valid_ratio > 0:
        return "keep", "has parseable candidates"
    return "keep", "empty source or no nonempty content"


def update_source_denylist_from_stats(
    denylist_path: Path,
    denied: set[str],
    active_sources: dict[str, str],
    source_stats: dict[str, dict[str, Any]],
    source_failures: list[dict[str, str]],
    min_lines: int,
    high_invalid_ratio: float,
) -> set[str]:
    failed_names = {
        failure.get("source", "")
        for failure in source_failures
        if failure.get("status") == "source_fetch_failed"
    }
    added: set[str] = set()
    updated = set(denied)
    for source, url in active_sources.items():
        if source in failed_names:
            continue
        stat = source_stats.get(source) or empty_source_stat(source, url)
        action, _reason = source_prune_action(stat, min_lines, high_invalid_ratio)
        if action == "auto_prune" and source not in updated and url not in updated:
            updated.add(source)
            added.add(source)
    if added:
        save_source_denylist(denylist_path, updated)
    return added


def update_source_cache(
    cache: dict[str, Any],
    active_sources: dict[str, str],
    source_stats: dict[str, dict[str, Any]],
    source_failures: list[dict[str, str]],
    invalid_threshold: int,
    quarantine_hours: float,
) -> None:
    now = time.time()
    cache_sources = cache.setdefault("sources", {})
    if not isinstance(cache_sources, dict):
        cache_sources = {}
        cache["sources"] = cache_sources
    failed_names = {failure.get("source", "") for failure in source_failures if failure.get("status") != "source_skipped_cached_invalid"}
    for name, url in active_sources.items():
        old = cache_sources.get(name) if isinstance(cache_sources.get(name), dict) else {}
        if old.get("url") != url:
            old = {}
        entry = dict(old)
        entry["url"] = url
        entry["last_checked_at"] = now
        stat = source_stats.get(name) or empty_source_stat(name, url)
        entry["last_raw_lines"] = int(stat.get("raw_lines") or 0)
        entry["last_nonempty_lines"] = int(stat.get("nonempty_lines") or 0)
        entry["last_valid_lines"] = int(stat.get("valid_lines") or 0)
        entry["last_invalid_lines"] = int(stat.get("invalid_lines") or 0)
        if name in failed_names:
            entry["last_status"] = "source_fetch_failed"
            cache_sources[name] = entry
            continue
        has_content = int(stat.get("nonempty_lines") or 0) > 0
        has_candidate = int(stat.get("valid_lines") or 0) > 0
        if has_candidate:
            entry["invalid_streak"] = 0
            entry["disabled_until"] = 0
            entry["last_status"] = "ok"
        elif has_content:
            streak = int(entry.get("invalid_streak") or 0) + 1
            entry["invalid_streak"] = streak
            entry["last_status"] = "no_parseable_candidates"
            if streak >= max(1, invalid_threshold):
                entry["disabled_until"] = now + max(0.0, quarantine_hours) * 3600
        else:
            entry["last_status"] = "empty"
        cache_sources[name] = entry


def parse_region(text: str) -> str | None:
    code_from_text = country_code_from_text(text)
    if code_from_text:
        return code_from_text
    for match in ASCII_REGION_RE.finditer(text.upper()):
        token = match.group(1)
        if token in COUNTRY_NAMES:
            return token
        if token in REGION_ALIASES:
            return REGION_ALIASES[token]
    return None


def parse_candidate(source: str, line: str) -> Candidate | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    left = line.split("#", 1)[0].strip()
    match = IP_PORT_RE.match(left)
    if not match:
        try:
            ip = ipaddress.ip_address(line)
        except ValueError:
            return None
        return Candidate(
            source=source,
            raw=line,
            host=str(ip),
            port=443,
            name=source,
            is_cloudflare=is_cloudflare_host(str(ip)),
            parse_format=f"bare_ipv{ip.version}_default_443",
            port_inferred=True,
        )
    host = match.group("host").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    port = int(match.group("port"))
    if port < 1 or port > 65535:
        return None

    desc = line.split("#", 1)[1].strip() if "#" in line else ""
    name = desc.split("|", 1)[0].strip() if desc else ""
    speed_match = SPEED_RE.search(line)
    latency_match = LATENCY_RE.search(line)
    declared_region = parse_region(line)
    return Candidate(
        source=source,
        raw=line,
        host=host,
        port=port,
        name=name,
        declared_speed=float(speed_match.group("speed")) if speed_match else None,
        declared_latency=float(latency_match.group("latency")) if latency_match else None,
        declared_region=declared_region,
        is_cloudflare=is_cloudflare_host(host),
        parse_format="endpoint_with_comment" if desc else "endpoint_no_comment",
        port_inferred=False,
    )


def curl_text(url: str, timeout: int = 20, proxy: str | None = None) -> tuple[bool, str]:
    cmd = [
        "curl.exe",
        "-sS",
        "-L",
        "--insecure",
        "--ssl-no-revoke",
        "--max-time",
        str(timeout),
    ]
    if proxy:
        cmd.extend(["--proxy", proxy])
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 3)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
    output = stdout.strip()
    if proc.returncode != 0:
        err = (stderr or output or f"curl exited {proc.returncode}").strip()
        return False, err
    return True, output


def curl_probe(url: str, timeout: int = 8, proxy: str | None = None) -> tuple[bool, int | None, float | None, str]:
    cmd = [
        "curl.exe",
        "-sS",
        "-L",
        "--insecure",
        "--ssl-no-revoke",
        "--max-time",
        str(timeout),
        "-o",
        "NUL" if os.name == "nt" else "/dev/null",
        "-w",
        "%{http_code} %{time_total}",
    ]
    if proxy:
        cmd.extend(["--proxy", proxy])
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 3)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, None, None, str(exc)
    stdout = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    parts = stdout.split()
    status_code: int | None = None
    elapsed_ms: float | None = None
    if parts:
        try:
            status_code = int(parts[-2] if len(parts) >= 2 else parts[-1])
        except ValueError:
            status_code = None
    if len(parts) >= 2:
        try:
            elapsed_ms = float(parts[-1]) * 1000
        except ValueError:
            elapsed_ms = None
    if proc.returncode != 0:
        return False, status_code, elapsed_ms, stderr or stdout or f"curl exited {proc.returncode}"
    if status_code is None:
        return False, status_code, elapsed_ms, "missing http status"
    ok = 200 <= status_code < 400
    return ok, status_code, elapsed_ms, "" if ok else f"http_status={status_code}"


def check_services(proxy: str, args: argparse.Namespace) -> tuple[int, bool | None, bool | None, bool | None, str]:
    if not args.service_check:
        return 0, None, None, None, ""
    checks = [
        ("google", args.google_url),
        ("youtube", args.youtube_url),
        ("gpt", args.gpt_url),
    ]
    results: dict[str, bool] = {}
    errors: list[str] = []
    for name, url in checks:
        if not url:
            results[name] = False
            errors.append(f"{name}: disabled")
            continue
        ok, status_code, elapsed_ms, error = curl_probe(url, timeout=args.service_timeout, proxy=proxy)
        if name == "gpt" and status_code in {400, 403}:
            ok = True
            error = f"http_status={status_code}; reachable_protected"
        results[name] = ok
        if not ok:
            detail = error or f"http_status={status_code}"
            errors.append(f"{name}: {detail}")
        elif args.verbose_services or (name == "gpt" and status_code in {400, 403}):
            errors.append(f"{name}: ok {status_code} {elapsed_ms:.0f}ms" if elapsed_ms is not None else f"{name}: ok")
    score = sum(1 for ok in results.values() if ok)
    return score, results.get("google"), results.get("youtube"), results.get("gpt"), " | ".join(errors)


def powershell_text(url: str, timeout: int = 20) -> tuple[bool, str]:
    command = (
        "& { param([string]$u,[int]$t) "
        "$ProgressPreference='SilentlyContinue'; "
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; "
        "(Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec $t).Content "
        "}"
    )
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command,
        url,
        str(timeout),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
    if proc.returncode != 0:
        return False, (stderr or stdout or f"powershell exited {proc.returncode}").strip()
    return True, stdout.strip()


def fetch_url(url: str, timeout: int = 20) -> tuple[bool, str]:
    context = ssl.create_default_context()
    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0 Safari/537.36"
                )
            },
        )
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            content = response.read().decode("utf-8", errors="replace")
            if content.strip():
                return True, content
            errors = ["urllib: empty response"]
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, UnicodeDecodeError) as exc:
        errors = [f"urllib: {exc}"]

    ok, content = powershell_text(url, timeout=timeout)
    if ok and content.strip():
        return True, content
    errors.append(f"powershell: {content if not ok else 'empty response'}")

    for proxy in [None, "http://127.0.0.1:7897", "http://127.0.0.1:7899", "socks5://127.0.0.1:7898"]:
        ok, content = curl_text(url, timeout=timeout, proxy=proxy)
        if ok and content.strip():
            return True, content
        label = proxy or "direct"
        errors.append(f"{label}: {content if not ok else 'empty response'}")
    return False, " | ".join(errors)


def fetch_sources(
    sources: dict[str, str],
    timeout: int,
    concurrency: int,
    retries: int,
) -> tuple[list[tuple[str, str]], list[dict[str, str]]]:
    rows: list[tuple[str, str]] = []
    failures: list[dict[str, str]] = []
    retry_items: list[tuple[str, str, str]] = []
    if not sources:
        return rows, failures
    with ThreadPoolExecutor(max_workers=min(max(1, concurrency), len(sources))) as pool:
        future_map = {pool.submit(fetch_url, url, timeout): (name, url) for name, url in sources.items()}
        for future in as_completed(future_map):
            name, url = future_map[future]
            ok, content = future.result()
            if not ok or not content.strip() or looks_like_html(content):
                reason = content if not ok else "empty response"
                if ok and content.strip() and looks_like_html(content):
                    reason = "html_or_404_response"
                retry_items.append((name, url, reason))
                continue
            for line in content.splitlines():
                rows.append((name, line))

    for name, url, first_error in retry_items:
        last_error = first_error
        success = False
        for attempt in range(max(0, retries)):
            ok, content = fetch_url(url, timeout=max(timeout, min(timeout * 2, timeout + 8)))
            if ok and content.strip() and not looks_like_html(content):
                for line in content.splitlines():
                    rows.append((name, line))
                success = True
                break
            last_error = content if not ok else ("html_or_404_response" if looks_like_html(content) else "empty response")
            time.sleep(1 + attempt)
        if not success:
            failures.append({"source": name, "url": url, "status": "source_fetch_failed", "error": last_error})
    return rows, failures


def looks_like_html(content: str) -> bool:
    sample = content[:2048].lower()
    return (
        "<!doctype html" in sample
        or "<html" in sample
        or "<head" in sample
        or "<body" in sample
        or "404 - 页面未找到" in content[:4096]
    )


def parse_candidates(rows: list[tuple[str, str]], sources: dict[str, str] | None = None) -> tuple[list[Candidate], list[dict[str, str]], dict[str, dict[str, Any]]]:
    candidates: dict[tuple[str, int], Candidate] = {}
    failures: list[dict[str, str]] = []
    source_stats: dict[str, dict[str, Any]] = {}
    if sources:
        for source, url in sources.items():
            source_stats[source] = empty_source_stat(source, url)
    for source, raw in rows:
        stat = source_stats.setdefault(source, empty_source_stat(source, sources.get(source, "") if sources else ""))
        stat["raw_lines"] += 1
        if raw.strip():
            stat["nonempty_lines"] += 1
        candidate = parse_candidate(source, raw)
        if candidate is None:
            if raw.strip():
                stat["invalid_lines"] += 1
                failures.append({"source": source, "raw": raw, "status": "parse_failed", "error": ""})
            continue
        stat["valid_lines"] += 1
        old = candidates.get(candidate.key)
        if old is None:
            candidates[candidate.key] = candidate
            continue
        old_speed = old.declared_speed if old.declared_speed is not None else -1.0
        new_speed = candidate.declared_speed if candidate.declared_speed is not None else -1.0
        if new_speed > old_speed:
            candidates[candidate.key] = candidate
    parsed = list(candidates.values())
    for item in parsed:
        stat = source_stats.setdefault(item.source, empty_source_stat(item.source, sources.get(item.source, "") if sources else ""))
        stat["unique_selected"] += 1
    parsed.sort(key=lambda item: (item.declared_speed is None, -(item.declared_speed or 0), item.endpoint))
    return parsed, failures, source_stats


def load_template(path: Path, template_name: str | None = None) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    proxies = config.get("proxies") or []
    if not isinstance(proxies, list):
        raise ValueError("template config has no proxy list")

    if template_name:
        for proxy in proxies:
            if isinstance(proxy, dict) and str(proxy.get("name")) == template_name:
                return dict(proxy)
        raise ValueError(f"template proxy not found: {template_name}")

    preferred: list[dict[str, Any]] = []
    fallback: list[dict[str, Any]] = []
    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        proxy_type = str(proxy.get("type", "")).lower()
        network = str(proxy.get("network", "")).lower()
        if proxy_type in {"vless", "vmess", "trojan"}:
            fallback.append(proxy)
        if proxy_type == "vless" and network == "ws" and bool(proxy.get("tls")):
            preferred.append(proxy)
    if preferred:
        return dict(preferred[0])
    if fallback:
        return dict(fallback[0])
    raise ValueError("no usable vless/vmess/trojan proxy template found")


def build_mihomo_config(template_proxy: dict[str, Any], candidate: Candidate, mixed_port: int, controller_port: int) -> dict[str, Any]:
    proxy = dict(template_proxy)
    proxy["name"] = "candidate"
    proxy["server"] = candidate.host
    proxy["port"] = candidate.port
    return {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{controller_port}",
        "proxies": [proxy],
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["candidate"],
            }
        ],
        "rules": ["MATCH,PROXY"],
    }


def candidate_proxy_name(index: int) -> str:
    return f"candidate-{index + 1:04d}"


def build_all_in_one_mihomo_config(
    template_proxy: dict[str, Any],
    candidates: list[Candidate],
    mixed_port: int,
    controller_port: int,
) -> tuple[dict[str, Any], dict[str, Candidate]]:
    proxies: list[dict[str, Any]] = []
    name_map: dict[str, Candidate] = {}
    for index, candidate in enumerate(candidates):
        name = candidate_proxy_name(index)
        proxy = dict(template_proxy)
        proxy["name"] = name
        proxy["server"] = candidate.host
        proxy["port"] = candidate.port
        proxies.append(proxy)
        name_map[name] = candidate
    proxy_names = list(name_map.keys())
    return (
        {
            "mixed-port": mixed_port,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "warning",
            "external-controller": f"127.0.0.1:{controller_port}",
            "proxies": proxies,
            "proxy-groups": [
                {
                    "name": "PROXY",
                    "type": "select",
                    "proxies": proxy_names or ["DIRECT"],
                }
            ],
            "rules": ["MATCH,PROXY"],
        },
        name_map,
    )


def controller_json(
    controller_port: int,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    timeout: int = 10,
) -> tuple[bool, dict[str, Any] | str]:
    url = f"http://127.0.0.1:{controller_port}{path}"
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")
    except Exception as exc:
        return False, str(exc)
    if not text.strip():
        return True, {}
    try:
        return True, json.loads(text)
    except json.JSONDecodeError:
        return False, text


def test_proxy_delay(
    controller_port: int,
    proxy_name: str,
    url: str,
    timeout_ms: int,
) -> tuple[str, int | None, str | None]:
    encoded_name = urllib.parse.quote(proxy_name, safe="")
    encoded_url = urllib.parse.quote(url, safe="")
    ok, data = controller_json(
        controller_port,
        "GET",
        f"/proxies/{encoded_name}/delay?timeout={timeout_ms}&url={encoded_url}",
        timeout=max(3, int(timeout_ms / 1000) + 3),
    )
    if not ok:
        return proxy_name, None, str(data)
    if not isinstance(data, dict):
        return proxy_name, None, str(data)
    delay = data.get("delay")
    if isinstance(delay, int):
        return proxy_name, delay, None
    return proxy_name, None, json.dumps(data, ensure_ascii=False)


def select_proxy(controller_port: int, proxy_name: str, timeout: int = 8) -> str | None:
    ok, data = controller_json(controller_port, "PUT", "/proxies/PROXY", {"name": proxy_name}, timeout=timeout)
    if ok:
        return None
    return str(data)


def wait_port(port: int, timeout: float = 6.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            try:
                sock.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.15)
    return False


def terminate_process(proc: subprocess.Popen[Any]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def start_mihomo(mihomo: Path, config_path: Path, data_dir: Path, log_path: Path) -> subprocess.Popen[Any]:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    log_file = log_path.open("ab")
    try:
        return subprocess.Popen(
            [str(mihomo), "-f", str(config_path), "-d", str(data_dir)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
    except Exception:
        log_file.close()
        raise


def parse_cloudflare_trace(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip()
    return fields


def geo_probe(proxy: str, timeout: int, name: str, url: str) -> tuple[str, str | None, str | None, str | None]:
    ok, text = curl_text(url, timeout=timeout, proxy=proxy)
    if not ok:
        return name, None, None, None
    try:
        if name == "cloudflare":
            fields = parse_cloudflare_trace(text)
            code = str(fields.get("loc") or "").upper() or None
            return name, code, fields.get("ip"), fields.get("colo")
        if name == "ping0":
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            ip = lines[0] if lines else None
            location = lines[1] if len(lines) > 1 else ""
            code = parse_region(location)
            if code and len(code) != 2:
                code = next((country_code for country_code, name_zh in COUNTRY_NAMES.items() if name_zh == code), code)
            return name, code.upper() if code and len(code) == 2 else None, ip, None

        data = json.loads(text)
        if name == "ipinfo":
            code = str(data.get("country") or "").upper() or None
            ip = data.get("ip")
        elif name == "ip_sb":
            code = str(data.get("country_code") or "").upper() or None
            ip = data.get("ip")
        elif name == "ipapi":
            code = str(data.get("country_code") or "").upper() or None
            ip = data.get("ip")
        elif name == "ipwhois":
            code = str(data.get("country_code") or "").upper() or None
            ip = data.get("ip")
        elif name == "ip_api":
            code = str(data.get("countryCode") or "").upper() or None
            ip = data.get("query")
        else:
            return name, None, None, None
        return name, code, str(ip) if ip else None, None
    except (json.JSONDecodeError, TypeError, ValueError):
        return name, None, None, None


def run_geo_probes_parallel(
    proxy: str,
    timeout: int,
    providers: list[str],
) -> list[tuple[str, str | None, str | None, str | None]]:
    providers = [provider for provider in providers if provider in GEO_PROVIDER_URLS]
    if not providers:
        return []
    results_by_name: dict[str, tuple[str, str | None, str | None, str | None]] = {}
    with ThreadPoolExecutor(max_workers=len(providers)) as pool:
        future_map = {
            pool.submit(geo_probe, proxy, timeout, provider, GEO_PROVIDER_URLS[provider]): provider
            for provider in providers
        }
        for future in as_completed(future_map):
            provider = future_map[future]
            try:
                results_by_name[provider] = future.result()
            except Exception:
                results_by_name[provider] = (provider, None, None, None)
    return [results_by_name[provider] for provider in providers if provider in results_by_name]


def select_geo_result(
    results: list[tuple[str, str | None, str | None, str | None]],
    provider_order: list[str],
) -> tuple[str | None, str, str | None, str | None, str]:
    counts: dict[str, int] = {}
    for result in results:
        _name, code, _ip, _colo = result
        if code:
            counts[code] = counts.get(code, 0) + 1

    evidence = ";".join(f"{name}:{code or '-'}" for name, code, _ip, _colo in results)
    selected_code: str | None = None
    if counts:
        max_votes = max(counts.values())
        winners = {code for code, count in counts.items() if count == max_votes}
        for provider in provider_order:
            for name, code, _ip, _colo in results:
                if name == provider and code in winners:
                    selected_code = code
                    break
            if selected_code:
                break
        if selected_code is None:
            selected_code = sorted(winners)[0]

    exit_ip: str | None = None
    colo: str | None = None
    if selected_code:
        for _name, code, ip, probe_colo in results:
            if code == selected_code:
                exit_ip = exit_ip or ip
                colo = colo or probe_colo
        if colo is None:
            for _name, _code, _ip, probe_colo in results:
                if probe_colo:
                    colo = probe_colo
                    break
        return selected_code, country_name(selected_code), exit_ip, colo, evidence

    for _name, _code, ip, probe_colo in results:
        exit_ip = exit_ip or ip
        colo = colo or probe_colo
    return None, "未知", exit_ip, colo, evidence


def detect_geo(proxy: str, timeout: int, providers: list[str]) -> tuple[str | None, str, str | None, str | None, str]:
    providers = [provider for provider in providers if provider in GEO_PROVIDER_URLS]
    if not providers:
        providers = list(DEFAULT_GEO_PROVIDERS_DAILY)

    if providers == DEFAULT_GEO_PROVIDERS_DAILY:
        first_stage = providers[:2]
        results = run_geo_probes_parallel(proxy, timeout, first_stage)
        codes = [code for _name, code, _ip, _colo in results if code]
        if len(set(codes)) <= 1 and codes:
            return select_geo_result(results, providers)
        if len(codes) == 1:
            return select_geo_result(results, providers)
        remaining = providers[2:]
        if remaining:
            results.extend(run_geo_probes_parallel(proxy, timeout, remaining))
        return select_geo_result(results, providers)

    results = run_geo_probes_parallel(proxy, timeout, providers)
    return select_geo_result(results, providers)


def measure_speed_once(proxy: str, url: str, timeout: int) -> tuple[float | None, float | None, int, str | None]:
    cmd = [
        "curl.exe",
        "-sS",
        "-L",
        "--insecure",
        "--ssl-no-revoke",
        "--proxy",
        proxy,
        "--max-time",
        str(timeout),
        "-o",
        "NUL" if os.name == "nt" else "/dev/null",
        "-w",
        "%{size_download} %{time_total}",
        url,
    ]
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 3)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, None, 0, str(exc)
    elapsed_ms = (time.monotonic() - start) * 1000
    stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
    parts = stdout.strip().split()
    if len(parts) < 2:
        if proc.returncode != 0:
            return None, None, 0, (stderr or stdout or f"curl exited {proc.returncode}").strip()
        return None, None, 0, "unexpected curl speed output"
    try:
        size = int(float(parts[-2]))
        total = float(parts[-1])
    except ValueError:
        return None, None, 0, f"invalid curl speed output: {stdout!r}"
    if total <= 0 or size <= 0:
        return None, elapsed_ms, size, "empty download"
    speed = size / total / 1024 / 1024
    if proc.returncode != 0:
        return speed, elapsed_ms, size, (stderr or stdout or f"curl exited {proc.returncode}").strip()
    return speed, elapsed_ms, size, None


def measure_speed(proxy: str, urls: list[str], timeout: int, min_download_bytes: int) -> tuple[float | None, float | None, str, str | None]:
    errors: list[str] = []
    for url in urls:
        speed, latency, size, error = measure_speed_once(proxy, url, timeout)
        if size < min_download_bytes:
            errors.append(f"{url}: {error or 'download too small'}; downloaded only {size} bytes")
            continue
        if error and speed is not None:
            return speed, latency, "partial_speed_ok", error
        if error:
            errors.append(f"{url}: {error}")
            continue
        return speed, latency, "ok", None
    return None, None, "speedtest_failed", " | ".join(errors) if errors else "no speed url tested"


def test_candidate(
    candidate: Candidate,
    template_proxy: dict[str, Any],
    worker_id: int,
    args: argparse.Namespace,
) -> TestResult:
    base = Path(args.workdir) / "workers" / str(worker_id)
    data_dir = base / "mihomo"
    logs_dir = Path(args.workdir) / "logs"
    data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    mixed_port = args.base_port + worker_id
    controller_port = args.controller_base_port + worker_id
    config = build_mihomo_config(template_proxy, candidate, mixed_port, controller_port)
    config_path = base / "mihomo_test.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, allow_unicode=True, sort_keys=False)

    log_path = logs_dir / f"worker_{worker_id}.log"
    proc: subprocess.Popen[Any] | None = None
    try:
        proc = start_mihomo(Path(args.mihomo), config_path, data_dir, log_path)
        if not wait_port(mixed_port, timeout=args.start_timeout):
            return TestResult(candidate, False, "mihomo_start_failed", "mixed port not ready")
        proxy = f"http://127.0.0.1:{mixed_port}"
        code, region, exit_ip, colo, geo_evidence = detect_geo(proxy, timeout=args.timeout, providers=args.geo_providers_resolved)
        speed, latency, speed_status, error = measure_speed(
            proxy,
            args.speed_urls,
            timeout=args.speed_timeout,
            min_download_bytes=args.min_download_bytes,
        )
        if speed is None:
            return TestResult(
                candidate,
                False,
                speed_status,
                error or "speed is empty",
                latency_ms=latency,
                exit_ip=exit_ip,
                exit_country_code=code,
                exit_region=region,
                cf_colo=colo,
                geo_evidence=geo_evidence,
            )
        if speed < args.min_speed:
            return TestResult(
                candidate,
                False,
                "below_min_speed",
                f"{speed:.2f}MB/s < {args.min_speed:.2f}MB/s",
                measured_speed=speed,
                latency_ms=latency,
                exit_ip=exit_ip,
                exit_country_code=code,
                exit_region=region,
                cf_colo=colo,
                geo_evidence=geo_evidence,
            )
        return TestResult(
            candidate,
            True,
            speed_status,
            measured_speed=speed,
            latency_ms=latency,
            exit_ip=exit_ip,
            exit_country_code=code,
            exit_region=region,
            cf_colo=colo,
            geo_evidence=geo_evidence,
        )
    except Exception as exc:
        return TestResult(candidate, False, "exception", str(exc))
    finally:
        if proc is not None:
            terminate_process(proc)


def write_raw(workdir: Path, rows: list[tuple[str, str]]) -> None:
    with (workdir / "bestcf_raw.txt").open("w", encoding="utf-8", newline="\n") as handle:
        for source, raw in rows:
            handle.write(f"[{source}] {raw}\n")


def write_parsed(workdir: Path, candidates: list[Candidate]) -> None:
    with (workdir / "bestcf_parsed.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "host",
                "port",
                "endpoint",
                "source",
                "name",
                "declared_region",
                "declared_latency_ms",
                "declared_speed_MBps",
                "is_cloudflare",
                "parse_format",
                "port_inferred",
                "raw_line",
            ],
        )
        writer.writeheader()
        for item in candidates:
            writer.writerow(
                {
                    "host": item.host,
                    "port": item.port,
                    "endpoint": item.endpoint,
                    "source": item.source,
                    "name": item.name,
                    "declared_region": item.declared_region or "",
                    "declared_latency_ms": item.declared_latency if item.declared_latency is not None else "",
                    "declared_speed_MBps": item.declared_speed if item.declared_speed is not None else "",
                    "is_cloudflare": item.is_cloudflare,
                    "parse_format": item.parse_format,
                    "port_inferred": item.port_inferred,
                    "raw_line": item.raw,
                }
            )


def source_status_from_stat(stat: dict[str, Any], failure: dict[str, str] | None) -> str:
    if failure:
        return failure.get("status", "source_fetch_failed")
    if int(stat.get("valid_lines") or 0) > 0:
        return "ok"
    if int(stat.get("nonempty_lines") or 0) > 0:
        return "no_parseable_candidates"
    if int(stat.get("raw_lines") or 0) > 0:
        return "empty_or_blank"
    return "not_checked"


def write_source_report(
    workdir: Path,
    sources: dict[str, str],
    source_stats: dict[str, dict[str, Any]],
    source_failures: list[dict[str, str]],
    cache: dict[str, Any],
) -> None:
    failures_by_source = {failure.get("source", ""): failure for failure in source_failures}
    cache_sources = cache.get("sources") if isinstance(cache.get("sources"), dict) else {}
    with (workdir / "bestcf_sources.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "source",
                "url",
                "status",
                "raw_lines",
                "nonempty_lines",
                "valid_lines",
                "invalid_lines",
                "valid_ratio",
                "invalid_ratio",
                "unique_selected",
                "invalid_streak",
                "disabled_until",
                "error",
            ],
        )
        writer.writeheader()
        for source, url in sources.items():
            stat = source_stats.get(source) or empty_source_stat(source, url)
            failure = failures_by_source.get(source)
            cache_entry = cache_sources.get(source) if isinstance(cache_sources.get(source), dict) else {}
            valid_ratio, invalid_ratio = source_ratios(stat)
            writer.writerow(
                {
                    "source": source,
                    "url": url,
                    "status": source_status_from_stat(stat, failure),
                    "raw_lines": int(stat.get("raw_lines") or 0),
                    "nonempty_lines": int(stat.get("nonempty_lines") or 0),
                    "valid_lines": int(stat.get("valid_lines") or 0),
                    "invalid_lines": int(stat.get("invalid_lines") or 0),
                    "valid_ratio": f"{valid_ratio:.6f}",
                    "invalid_ratio": f"{invalid_ratio:.6f}",
                    "unique_selected": int(stat.get("unique_selected") or 0),
                    "invalid_streak": cache_entry.get("invalid_streak", ""),
                    "disabled_until": format_timestamp(cache_entry.get("disabled_until")),
                    "error": failure.get("error", "") if failure else "",
                }
            )


def write_source_prune_report(
    workdir: Path,
    sources: dict[str, str],
    source_stats: dict[str, dict[str, Any]],
    source_failures: list[dict[str, str]],
    denied: set[str],
    newly_denied: set[str],
    min_lines: int,
    high_invalid_ratio: float,
) -> None:
    failures_by_source = {failure.get("source", ""): failure for failure in source_failures}
    with (workdir / DEFAULT_SOURCE_PRUNE_REPORT_NAME).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "source",
                "url",
                "status",
                "raw_lines",
                "nonempty_lines",
                "valid_lines",
                "invalid_lines",
                "valid_ratio",
                "invalid_ratio",
                "unique_selected",
                "prune_action",
                "reason",
                "in_denylist",
                "newly_denied",
                "error",
            ],
        )
        writer.writeheader()
        for source, url in sources.items():
            stat = source_stats.get(source) or empty_source_stat(source, url)
            failure = failures_by_source.get(source)
            valid_ratio, invalid_ratio = source_ratios(stat)
            action, reason = source_prune_action(stat, min_lines, high_invalid_ratio)
            in_denylist = source in denied or url in denied
            if failure and failure.get("status") == "source_pruned_by_denylist":
                action = "already_pruned"
                reason = "hard denylist removed this source before download"
            elif failure and failure.get("status") == "source_fetch_failed":
                action = "keep"
                reason = "fetch failed; not enough evidence to prune safely"
            writer.writerow(
                {
                    "source": source,
                    "url": url,
                    "status": source_status_from_stat(stat, failure),
                    "raw_lines": int(stat.get("raw_lines") or 0),
                    "nonempty_lines": int(stat.get("nonempty_lines") or 0),
                    "valid_lines": int(stat.get("valid_lines") or 0),
                    "invalid_lines": int(stat.get("invalid_lines") or 0),
                    "valid_ratio": f"{valid_ratio:.6f}",
                    "invalid_ratio": f"{invalid_ratio:.6f}",
                    "unique_selected": int(stat.get("unique_selected") or 0),
                    "prune_action": action,
                    "reason": reason,
                    "in_denylist": in_denylist,
                    "newly_denied": source in newly_denied,
                    "error": failure.get("error", "") if failure else "",
                }
            )


def result_region(result: TestResult) -> str:
    return result.exit_region or country_name(result.exit_country_code) or "未知"


def result_latency(result: TestResult) -> float:
    return result.latency_ms if result.latency_ms is not None else float("inf")


def result_quality_key(result: TestResult) -> tuple[float, int, bool, float, str]:
    return (
        result_latency(result),
        -result.service_score,
        result.measured_speed is None,
        -(result.measured_speed or 0),
        result.candidate.endpoint,
    )


def median_number(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def dynamic_region_limit(target_count: int, region_count: int, configured_limit: int) -> int:
    if configured_limit > 0:
        return configured_limit
    if target_count <= 0:
        return 0
    if region_count >= 20:
        return 30
    if region_count >= 10:
        return 40
    return 60


def add_final_result(
    selected: list[TestResult],
    selected_keys: set[tuple[str, int]],
    selected_counts: dict[str, int],
    result: TestResult,
    target_count: int,
    region_limit: int,
    enforce_region_limit: bool,
) -> bool:
    if target_count > 0 and len(selected) >= target_count:
        return False
    if result.candidate.key in selected_keys:
        return False
    region = result_region(result)
    if enforce_region_limit and region_limit > 0 and selected_counts.get(region, 0) >= region_limit:
        return False
    selected.append(result)
    selected_keys.add(result.candidate.key)
    selected_counts[region] = selected_counts.get(region, 0) + 1
    return True


def select_final_results(ok_results: list[TestResult], args: argparse.Namespace) -> list[TestResult]:
    target_count = args.max_final_candidates
    if not ok_results:
        return []

    groups: dict[str, list[TestResult]] = {}
    for result in ok_results:
        groups.setdefault(result_region(result), []).append(result)
    for items in groups.values():
        items.sort(key=result_quality_key)

    region_limit = dynamic_region_limit(target_count, len(groups), args.country_max)
    selected: list[TestResult] = []
    selected_keys: set[tuple[str, int]] = set()
    selected_counts: dict[str, int] = {}

    # First pass guarantees region coverage. Scarce regions get preference, but
    # high-latency scarce nodes are left for the final fallback pass.
    for region, items in sorted(groups.items(), key=lambda item: (len(item[1]), item[0])):
        size = len(items)
        if size <= 3:
            keep_limit = min(size, 3)
            stage_items = [item for item in items if result_latency(item) <= args.final_preferred_latency_ms]
        elif size <= 10:
            keep_limit = min(size, 5)
            stage_items = items
        elif size <= 30:
            keep_limit = min(size, 5)
            stage_items = items
        else:
            keep_limit = min(size, 3)
            stage_items = items
        for result in stage_items[:keep_limit]:
            add_final_result(
                selected,
                selected_keys,
                selected_counts,
                result,
                target_count,
                region_limit,
                enforce_region_limit=False,
            )

    if target_count <= 0 or len(selected) < target_count:
        remaining = [result for result in ok_results if result.candidate.key not in selected_keys]
        remaining.sort(
            key=lambda result: (
                result_latency(result),
                -result.service_score,
                result.measured_speed is None,
                -(result.measured_speed or 0),
                selected_counts.get(result_region(result), 0),
                result.candidate.endpoint,
            )
        )
        for result in remaining:
            add_final_result(
                selected,
                selected_keys,
                selected_counts,
                result,
                target_count,
                region_limit,
                enforce_region_limit=True,
            )

    if target_count > 0 and len(selected) < target_count:
        fallback = [result for result in ok_results if result.candidate.key not in selected_keys]
        fallback.sort(key=result_quality_key)
        for result in fallback:
            add_final_result(
                selected,
                selected_keys,
                selected_counts,
                result,
                target_count,
                region_limit,
                enforce_region_limit=args.country_max > 0,
            )

    return selected[:target_count] if target_count > 0 else selected


def write_region_counts(path: Path, ok_results: list[TestResult], final_results: list[TestResult]) -> None:
    groups: dict[str, list[TestResult]] = {}
    final_counts: dict[str, int] = {}
    for result in ok_results:
        groups.setdefault(result_region(result), []).append(result)
    for result in final_results:
        region = result_region(result)
        final_counts[region] = final_counts.get(region, 0) + 1

    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "exit_region_name",
                "exit_country_code",
                "eligible_count",
                "selected_count",
                "min_latency_ms",
                "median_latency_ms",
            ],
        )
        writer.writeheader()
        for region, items in sorted(groups.items(), key=lambda item: (len(item[1]), item[0])):
            latencies = [result_latency(result) for result in items if result_latency(result) != float("inf")]
            codes = sorted({(result.exit_country_code or "").upper() for result in items if result.exit_country_code})
            median = median_number(latencies)
            writer.writerow(
                {
                    "exit_region_name": region,
                    "exit_country_code": ",".join(codes),
                    "eligible_count": len(items),
                    "selected_count": final_counts.get(region, 0),
                    "min_latency_ms": f"{min(latencies):.0f}" if latencies else "",
                    "median_latency_ms": f"{median:.0f}" if median is not None else "",
                }
            )


def parse_geo_evidence(evidence: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in str(evidence or "").split(";"):
        if ":" not in part:
            continue
        provider, code = part.split(":", 1)
        provider = provider.strip()
        code = code.strip().upper()
        if provider:
            result[provider] = "" if code == "-" else code
    return result


def compact_counter(counter: collections.Counter[str], limit: int = 8) -> str:
    return "|".join(f"{key}:{value}" for key, value in counter.most_common(limit))


def write_geo_provider_stats(path: Path, results: list[TestResult], providers: list[str]) -> None:
    geo_results = [result for result in results if result.exit_country_code and result.geo_evidence]
    total = len(geo_results)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "provider",
                "total_geo_results",
                "covered_count",
                "coverage_rate",
                "agree_count",
                "agree_rate",
                "disagree_count",
                "unknown_count",
                "gb_count",
                "provider_country_top",
                "selected_country_top",
            ],
        )
        writer.writeheader()
        selected_counter = collections.Counter(
            (result.exit_country_code or "").upper()
            for result in geo_results
            if result.exit_country_code
        )
        for provider in providers:
            covered = 0
            agree = 0
            unknown = 0
            provider_counter: collections.Counter[str] = collections.Counter()
            for result in geo_results:
                evidence = parse_geo_evidence(result.geo_evidence)
                code = evidence.get(provider, "")
                if not code:
                    unknown += 1
                    continue
                covered += 1
                provider_counter[code] += 1
                if code == (result.exit_country_code or "").upper():
                    agree += 1
            disagree = max(0, covered - agree)
            writer.writerow(
                {
                    "provider": provider,
                    "total_geo_results": total,
                    "covered_count": covered,
                    "coverage_rate": f"{covered / total:.6f}" if total else "0.000000",
                    "agree_count": agree,
                    "agree_rate": f"{agree / covered:.6f}" if covered else "0.000000",
                    "disagree_count": disagree,
                    "unknown_count": unknown,
                    "gb_count": provider_counter.get("GB", 0),
                    "provider_country_top": compact_counter(provider_counter),
                    "selected_country_top": compact_counter(selected_counter),
                }
            )


def write_results(
    workdir: Path,
    results: list[TestResult],
    parse_failures: list[dict[str, str]],
    source_failures: list[dict[str, str]],
    args: argparse.Namespace,
) -> Path:
    tested_path = workdir / "bestcf_tested.csv"
    failed_path = workdir / "bestcf_failed.csv"
    final_path = workdir / "bestcf_final.txt"
    other_regions_path = workdir / "bestcf_other_regions.csv"
    region_counts_path = workdir / "bestcf_region_counts.csv"
    provider_stats_path = workdir / "bestcf_geo_provider_stats.csv"

    with tested_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "host",
                "port",
                "endpoint",
                "source",
                "declared_region",
                "declared_speed_MBps",
                "measured_speed_MBps",
                "latency_ms",
                "exit_ip",
                "exit_country_code",
                "exit_region_name",
                "cf_colo",
                "geo_evidence",
                "geo_cache_status",
                "is_cloudflare",
                "service_score",
                "google_ok",
                "youtube_ok",
                "gpt_ok",
                "service_error",
                "selection_stage",
                "status",
                "error",
                "raw_line",
            ],
        )
        writer.writeheader()
        for result in results:
            item = result.candidate
            writer.writerow(
                {
                    "host": item.host,
                    "port": item.port,
                    "endpoint": item.endpoint,
                    "source": item.source,
                    "declared_region": item.declared_region or "",
                    "declared_speed_MBps": item.declared_speed if item.declared_speed is not None else "",
                    "measured_speed_MBps": f"{result.measured_speed:.2f}" if result.measured_speed is not None else "",
                    "latency_ms": f"{result.latency_ms:.0f}" if result.latency_ms is not None else "",
                    "exit_ip": result.exit_ip or "",
                    "exit_country_code": result.exit_country_code or "",
                    "exit_region_name": result.exit_region,
                    "cf_colo": result.cf_colo or "",
                    "geo_evidence": result.geo_evidence,
                    "geo_cache_status": result.geo_cache_status,
                    "is_cloudflare": item.is_cloudflare,
                    "service_score": result.service_score,
                    "google_ok": result.google_ok if result.google_ok is not None else "",
                    "youtube_ok": result.youtube_ok if result.youtube_ok is not None else "",
                    "gpt_ok": result.gpt_ok if result.gpt_ok is not None else "",
                    "service_error": result.service_error,
                    "selection_stage": result.selection_stage,
                    "status": result.status,
                    "error": result.error,
                    "raw_line": item.raw,
                }
            )

    with failed_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["source", "host", "port", "status", "error", "raw_line"])
        writer.writeheader()
        for failure in source_failures:
            writer.writerow(
                {
                    "source": failure.get("source", ""),
                    "host": "",
                    "port": "",
                    "status": failure.get("status", "source_fetch_failed"),
                    "error": failure.get("error", ""),
                    "raw_line": failure.get("url", ""),
                }
            )
        for failure in parse_failures:
            writer.writerow(
                {
                    "source": failure.get("source", ""),
                    "host": "",
                    "port": "",
                    "status": failure.get("status", "parse_failed"),
                    "error": failure.get("error", ""),
                    "raw_line": failure.get("raw", ""),
                }
            )
        for result in results:
            if result.ok:
                continue
            writer.writerow(
                {
                    "source": result.candidate.source,
                    "host": result.candidate.host,
                    "port": result.candidate.port,
                    "status": result.status,
                    "error": result.error,
                    "raw_line": result.candidate.raw,
                }
            )

    ok_results = [result for result in results if result.ok]
    final_results = select_final_results(ok_results, args)
    write_region_counts(region_counts_path, ok_results, final_results)
    write_geo_provider_stats(provider_stats_path, results, args.geo_providers_resolved)

    counters: dict[str, int] = {}
    with final_path.open("w", encoding="utf-8", newline="\n") as handle:
        for result in final_results:
            region = result.exit_region or "未知"
            counters[region] = counters.get(region, 0) + 1
            line = f"{result.candidate.endpoint}#{region}-{counters[region]}"
            if result.measured_speed is not None:
                line += f"|{result.measured_speed:.2f}MB/s"
            handle.write(line + "\n")

    other_region_results = [
        result for result in results
        if result.status == "region_not_preferred" or (
            result.ok
            and result.exit_country_code
            and result.exit_country_code.upper() not in set(args.preferred_country_order or PREFERRED_COUNTRY_ORDER)
        )
    ]
    other_region_results.sort(
        key=lambda result: (
            result.exit_country_code or "",
            result.latency_ms or 10**9,
            result.candidate.endpoint,
        )
    )
    with other_regions_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "exit_country_code",
                "exit_region_name",
                "host",
                "port",
                "endpoint",
                "source",
                "latency_ms",
                "cf_colo",
                "geo_evidence",
                "geo_cache_status",
                "status",
                "error",
                "raw_line",
            ],
        )
        writer.writeheader()
        for result in other_region_results:
            writer.writerow(
                {
                    "exit_country_code": result.exit_country_code or "",
                    "exit_region_name": result.exit_region,
                    "host": result.candidate.host,
                    "port": result.candidate.port,
                    "endpoint": result.candidate.endpoint,
                    "source": result.candidate.source,
                    "latency_ms": f"{result.latency_ms:.0f}" if result.latency_ms is not None else "",
                    "cf_colo": result.cf_colo or "",
                    "geo_evidence": result.geo_evidence,
                    "geo_cache_status": result.geo_cache_status,
                    "status": result.status,
                    "error": result.error,
                    "raw_line": result.candidate.raw,
                }
            )
    return final_path


def clean_workers(workdir: Path) -> None:
    for dirname in ["workers", "latency", "geo_workers", "speed_workers"]:
        target = workdir / dirname
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
    (workdir / "logs").mkdir(parents=True, exist_ok=True)


def run_tests(candidates: list[Candidate], template_proxy: dict[str, Any], args: argparse.Namespace) -> list[TestResult]:
    results: list[TestResult] = []
    total = len(candidates)
    if total == 0:
        return results
    worker_ids: queue.Queue[int] = queue.Queue()
    for worker_id in range(args.concurrency):
        worker_ids.put(worker_id)

    def run_with_worker(candidate: Candidate) -> TestResult:
        worker_id = worker_ids.get()
        try:
            return test_candidate(candidate, template_proxy, worker_id, args)
        finally:
            worker_ids.put(worker_id)

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        future_map = {pool.submit(run_with_worker, candidate): candidate for candidate in candidates}
        done = 0
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            done += 1
            speed = f"{result.measured_speed:.2f}MB/s" if result.measured_speed is not None else "-"
            print(f"[{done}/{total}] {result.candidate.endpoint} {result.status} {result.exit_region} {speed}", flush=True)
    return results


def write_latency_results(workdir: Path, rows: list[dict[str, Any]]) -> None:
    path = workdir / "bestcf_latency.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "host",
                "port",
                "endpoint",
                "proxy_name",
                "source",
                "delay_ms",
                "latency_status",
                "error",
                "declared_region",
                "declared_speed_MBps",
                "raw_line",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def run_latency_tests(
    candidates: list[Candidate],
    template_proxy: dict[str, Any],
    args: argparse.Namespace,
) -> tuple[list[tuple[str, Candidate, int]], list[TestResult]]:
    workdir = Path(args.workdir)
    base = workdir / "latency"
    data_dir = base / "mihomo"
    logs_dir = workdir / "logs"
    data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    config, name_map = build_all_in_one_mihomo_config(
        template_proxy,
        candidates,
        args.base_port,
        args.controller_base_port,
    )
    config_path = base / "mihomo_latency.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, allow_unicode=True, sort_keys=False)

    proc: subprocess.Popen[Any] | None = None
    latency_rows: list[dict[str, Any]] = []
    failed_results: list[TestResult] = []
    eligible: list[tuple[str, Candidate, int]] = []
    try:
        proc = start_mihomo(Path(args.mihomo), config_path, data_dir, logs_dir / "latency.log")
        if not wait_port(args.base_port, timeout=args.start_timeout):
            return [], [TestResult(candidate, False, "mihomo_start_failed", "mixed port not ready") for candidate in candidates]

        total = len(name_map)
        done = 0
        with ThreadPoolExecutor(max_workers=args.latency_concurrency) as pool:
            future_map = {
                pool.submit(
                    test_proxy_delay,
                    args.controller_base_port,
                    proxy_name,
                    args.latency_url,
                    args.latency_timeout,
                ): proxy_name
                for proxy_name in name_map
            }
            for future in as_completed(future_map):
                proxy_name, delay, error = future.result()
                candidate = name_map[proxy_name]
                done += 1
                if delay is None:
                    status = "latency_failed"
                    failed_results.append(
                        TestResult(candidate, False, status, error or "delay test failed", latency_ms=None)
                    )
                elif delay > args.latency_threshold:
                    status = "latency_too_high"
                    failed_results.append(
                        TestResult(
                            candidate,
                            False,
                            status,
                            f"{delay}ms > {args.latency_threshold}ms",
                            latency_ms=float(delay),
                        )
                    )
                else:
                    status = "latency_ok"
                    eligible.append((proxy_name, candidate, delay))
                latency_rows.append(
                    {
                        "host": candidate.host,
                        "port": candidate.port,
                        "endpoint": candidate.endpoint,
                        "proxy_name": proxy_name,
                        "source": candidate.source,
                        "delay_ms": delay if delay is not None else "",
                        "latency_status": status,
                        "error": error or "",
                        "declared_region": candidate.declared_region or "",
                        "declared_speed_MBps": candidate.declared_speed if candidate.declared_speed is not None else "",
                        "raw_line": candidate.raw,
                    }
                )
                if done % 25 == 0 or done == total:
                    print(f"[latency {done}/{total}] eligible={len(eligible)} failed={len(failed_results)}", flush=True)
    finally:
        if proc is not None:
            terminate_process(proc)

    write_latency_results(workdir, latency_rows)
    eligible.sort(key=lambda item: (item[2], item[1].endpoint))
    return eligible, failed_results


def split_evenly(items: list[tuple[Candidate, int]], parts: int) -> list[list[tuple[Candidate, int]]]:
    parts = max(1, parts)
    chunks = [[] for _ in range(parts)]
    for index, item in enumerate(items):
        chunks[index % parts].append(item)
    return chunks


def test_speed_geo_chunk(
    chunk: list[tuple[Candidate, int]],
    template_proxy: dict[str, Any],
    worker_id: int,
    args: argparse.Namespace,
) -> list[TestResult]:
    if not chunk:
        return []
    candidates = [candidate for candidate, _delay in chunk]
    delay_map = {candidate.key: delay for candidate, delay in chunk}
    base = Path(args.workdir) / "speed_workers" / str(worker_id)
    data_dir = base / "mihomo"
    logs_dir = Path(args.workdir) / "logs"
    data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    mixed_port = args.base_port + 100 + worker_id
    controller_port = args.controller_base_port + 100 + worker_id
    config, name_map = build_all_in_one_mihomo_config(template_proxy, candidates, mixed_port, controller_port)
    config_path = base / "mihomo_speed.yaml"
    with config_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, allow_unicode=True, sort_keys=False)

    proc: subprocess.Popen[Any] | None = None
    results: list[TestResult] = []
    try:
        proc = start_mihomo(Path(args.mihomo), config_path, data_dir, logs_dir / f"speed_worker_{worker_id}.log")
        if not wait_port(mixed_port, timeout=args.start_timeout):
            return [TestResult(candidate, False, "mihomo_start_failed", "mixed port not ready") for candidate in candidates]
        proxy = f"http://127.0.0.1:{mixed_port}"
        for proxy_name, candidate in name_map.items():
            switch_error = select_proxy(controller_port, proxy_name, timeout=args.timeout)
            delay = float(delay_map.get(candidate.key, 0))
            if switch_error:
                results.append(TestResult(candidate, False, "select_proxy_failed", switch_error, latency_ms=delay))
                continue
            code, region, exit_ip, colo, geo_evidence = detect_geo(proxy, timeout=args.timeout, providers=args.geo_providers_resolved)
            if not args.allow_other_regions and code and code.upper() not in args.preferred_countries:
                results.append(
                    TestResult(
                        candidate,
                        False,
                        "region_not_preferred",
                        f"{code} not in {','.join(sorted(args.preferred_countries))}",
                        latency_ms=delay,
                        exit_ip=exit_ip,
                        exit_country_code=code,
                        exit_region=region,
                        cf_colo=colo,
                        geo_evidence=geo_evidence,
                    )
                )
                continue
            if not args.allow_unknown_region and not code:
                results.append(
                    TestResult(
                        candidate,
                        False,
                        "region_unknown",
                        "exit country unavailable",
                        latency_ms=delay,
                        exit_ip=exit_ip,
                        exit_country_code=code,
                        exit_region=region,
                        cf_colo=colo,
                        geo_evidence=geo_evidence,
                    )
                )
                continue
            speed, speed_latency, speed_status, error = measure_speed(
                proxy,
                args.speed_urls,
                timeout=args.speed_timeout,
                min_download_bytes=args.min_download_bytes,
            )
            if speed is None:
                results.append(
                    TestResult(
                        candidate,
                        False,
                        speed_status,
                        error or "speed is empty",
                        latency_ms=delay,
                        exit_ip=exit_ip,
                        exit_country_code=code,
                        exit_region=region,
                        cf_colo=colo,
                        geo_evidence=geo_evidence,
                    )
                )
                continue
            if speed < args.min_speed:
                results.append(
                    TestResult(
                        candidate,
                        False,
                        "below_min_speed",
                        f"{speed:.2f}MB/s < {args.min_speed:.2f}MB/s",
                        measured_speed=speed,
                        latency_ms=delay or speed_latency,
                        exit_ip=exit_ip,
                        exit_country_code=code,
                        exit_region=region,
                        cf_colo=colo,
                        geo_evidence=geo_evidence,
                    )
                )
                continue
            results.append(
                TestResult(
                    candidate,
                    True,
                    speed_status,
                    measured_speed=speed,
                    latency_ms=delay or speed_latency,
                    exit_ip=exit_ip,
                    exit_country_code=code,
                    exit_region=region,
                    cf_colo=colo,
                    geo_evidence=geo_evidence,
                )
            )
    except Exception as exc:
        for candidate in candidates:
            results.append(TestResult(candidate, False, "exception", str(exc), latency_ms=float(delay_map.get(candidate.key, 0))))
    finally:
        if proc is not None:
            terminate_process(proc)
    return results


def test_geo_chunk(
    chunk: list[tuple[str, Candidate, int]],
    template_proxy: dict[str, Any],
    worker_id: int,
    args: argparse.Namespace,
) -> list[TestResult]:
    if not chunk:
        return []
    candidates = [candidate for _proxy_name, candidate, _delay in chunk]
    delay_map = {candidate.key: delay for _proxy_name, candidate, delay in chunk}
    base = Path(args.workdir) / "geo_workers" / str(worker_id)
    data_dir = base / "mihomo"
    logs_dir = Path(args.workdir) / "logs"
    data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    mixed_port = args.base_port + 200 + worker_id
    controller_port = args.controller_base_port + 200 + worker_id
    config, name_map = build_all_in_one_mihomo_config(template_proxy, candidates, mixed_port, controller_port)
    config_path = base / "mihomo_geo.yaml"
    with config_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, allow_unicode=True, sort_keys=False)

    proc: subprocess.Popen[Any] | None = None
    results: list[TestResult] = []
    try:
        proc = start_mihomo(Path(args.mihomo), config_path, data_dir, logs_dir / f"geo_worker_{worker_id}.log")
        if not wait_port(mixed_port, timeout=args.start_timeout):
            return [TestResult(candidate, False, "mihomo_start_failed", "mixed port not ready") for candidate in candidates]
        proxy = f"http://127.0.0.1:{mixed_port}"
        for proxy_name, candidate in name_map.items():
            delay = float(delay_map.get(candidate.key, 0))
            switch_error = select_proxy(controller_port, proxy_name, timeout=args.timeout)
            if switch_error:
                results.append(TestResult(candidate, False, "select_proxy_failed", switch_error, latency_ms=delay))
                continue
            cache_status, cache_entry = geo_cache_lookup(candidate, args, time.time())
            if cache_entry:
                cached = test_result_from_geo_cache(candidate, delay, cache_entry, cache_status)
                code = cached.exit_country_code
                region = cached.exit_region
                exit_ip = cached.exit_ip
                colo = cached.cf_colo
                geo_evidence = cached.geo_evidence
                geo_cache_status = cache_status
            else:
                code, region, exit_ip, colo, geo_evidence = detect_geo(
                    proxy,
                    timeout=args.timeout,
                    providers=args.geo_providers_resolved,
                )
                geo_cache_status = cache_status
            if not args.allow_other_regions and code and code.upper() not in args.preferred_countries:
                results.append(
                    TestResult(
                        candidate,
                        False,
                        "region_not_preferred",
                        f"{code} not in {','.join(sorted(args.preferred_countries))}",
                        latency_ms=delay,
                        exit_ip=exit_ip,
                        exit_country_code=code,
                        exit_region=region,
                        cf_colo=colo,
                        geo_evidence=geo_evidence,
                        geo_cache_status=geo_cache_status,
                    )
                )
                continue
            if not args.allow_unknown_region and not code:
                results.append(
                    TestResult(
                        candidate,
                        False,
                        "region_unknown",
                        "exit country unavailable",
                        latency_ms=delay,
                        exit_ip=exit_ip,
                        exit_country_code=code,
                        exit_region=region,
                        cf_colo=colo,
                        geo_evidence=geo_evidence,
                        geo_cache_status=geo_cache_status,
                    )
                )
                continue
            service_score, google_ok, youtube_ok, gpt_ok, service_error = check_services(proxy, args)
            if args.service_check and service_score < args.min_service_score:
                result = TestResult(
                    candidate,
                    False,
                    "service_check_failed",
                    f"service_score={service_score} < {args.min_service_score}",
                    latency_ms=delay,
                    exit_ip=exit_ip,
                    exit_country_code=code,
                    exit_region=region,
                    cf_colo=colo,
                    geo_evidence=geo_evidence,
                    geo_cache_status=geo_cache_status,
                    service_score=service_score,
                    google_ok=google_ok,
                    youtube_ok=youtube_ok,
                    gpt_ok=gpt_ok,
                    service_error=service_error,
                )
                geo_cache_update(candidate, result, args, time.time())
                results.append(result)
                continue
            result = TestResult(
                candidate,
                True,
                "geo_only" if geo_cache_status != "hit" else "geo_cached",
                latency_ms=delay,
                exit_ip=exit_ip,
                exit_country_code=code,
                exit_region=region,
                cf_colo=colo,
                geo_evidence=geo_evidence,
                geo_cache_status=geo_cache_status,
                service_score=service_score,
                google_ok=google_ok,
                youtube_ok=youtube_ok,
                gpt_ok=gpt_ok,
                service_error=service_error,
            )
            geo_cache_update(candidate, result, args, time.time())
            results.append(result)
    except Exception as exc:
        for candidate in candidates:
            results.append(TestResult(candidate, False, "exception", str(exc), latency_ms=float(delay_map.get(candidate.key, 0))))
    finally:
        if proc is not None:
            terminate_process(proc)
    return results


def test_speed_chunk_from_geo(
    chunk: list[TestResult],
    template_proxy: dict[str, Any],
    worker_id: int,
    args: argparse.Namespace,
) -> list[TestResult]:
    if not chunk:
        return []
    candidates = [result.candidate for result in chunk]
    geo_map = {result.candidate.key: result for result in chunk}
    base = Path(args.workdir) / "speed_workers" / str(worker_id)
    data_dir = base / "mihomo"
    logs_dir = Path(args.workdir) / "logs"
    data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    mixed_port = args.base_port + 100 + worker_id
    controller_port = args.controller_base_port + 100 + worker_id
    config, name_map = build_all_in_one_mihomo_config(template_proxy, candidates, mixed_port, controller_port)
    config_path = base / "mihomo_speed.yaml"
    with config_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, allow_unicode=True, sort_keys=False)

    proc: subprocess.Popen[Any] | None = None
    results: list[TestResult] = []
    try:
        proc = start_mihomo(Path(args.mihomo), config_path, data_dir, logs_dir / f"speed_worker_{worker_id}.log")
        if not wait_port(mixed_port, timeout=args.start_timeout):
            return [
                dataclasses.replace(geo_map[candidate.key], ok=True, status="geo_only", error="speed mihomo start failed")
                for candidate in candidates
            ]
        proxy = f"http://127.0.0.1:{mixed_port}"
        for proxy_name, candidate in name_map.items():
            geo_result = geo_map[candidate.key]
            switch_error = select_proxy(controller_port, proxy_name, timeout=args.timeout)
            if switch_error:
                results.append(dataclasses.replace(geo_result, ok=True, status="geo_only", error=switch_error))
                continue
            speed, speed_latency, speed_status, error = measure_speed(
                proxy,
                args.speed_urls,
                timeout=args.speed_timeout,
                min_download_bytes=args.min_download_bytes,
            )
            if speed is None:
                results.append(dataclasses.replace(geo_result, ok=True, status="geo_only", error=error or "speed failed"))
                continue
            if speed < args.min_speed:
                results.append(
                    dataclasses.replace(
                        geo_result,
                        ok=True,
                        status="geo_only",
                        error=f"{speed:.2f}MB/s < {args.min_speed:.2f}MB/s",
                    )
                )
                continue
            results.append(
                dataclasses.replace(
                    geo_result,
                    ok=True,
                    status=speed_status,
                    measured_speed=speed,
                    latency_ms=geo_result.latency_ms or speed_latency,
                    error=error or "",
                )
            )
    except Exception as exc:
        for candidate in candidates:
            results.append(dataclasses.replace(geo_map[candidate.key], ok=True, status="geo_only", error=str(exc)))
    finally:
        if proc is not None:
            terminate_process(proc)
    return results


def select_speed_sample(geo_results: list[TestResult], bands: list[tuple[int, int]], speed_limit: int) -> set[tuple[str, int]]:
    if speed_limit <= 0:
        return set()
    ordered = list(geo_results)
    selected: list[TestResult] = []
    offset = 0
    for band_size, take_count in bands:
        band = ordered[offset : offset + band_size]
        selected.extend(band[:take_count])
        offset += band_size
    selected = selected[:speed_limit]
    return {result.candidate.key for result in selected}


def speed_budget_remaining(args: argparse.Namespace, reserve_seconds: float = 5.0) -> float:
    if args.time_budget <= 0:
        return float("inf")
    elapsed = time.monotonic() - args.run_started_at
    return args.time_budget - elapsed - reserve_seconds


def budgeted_speed_sample_limit(args: argparse.Namespace, selected_count: int) -> int:
    if selected_count <= 0:
        return 0
    remaining_budget = speed_budget_remaining(args)
    if remaining_budget == float("inf"):
        return selected_count
    if remaining_budget <= 0:
        return 0

    worker_count = max(1, args.speed_concurrency)
    per_wave_seconds = max(float(args.speed_timeout), 0.1)
    startup_seconds = max(float(args.start_timeout), 0.0) + 2.0
    affordable_waves = int((remaining_budget - startup_seconds) / per_wave_seconds)
    if affordable_waves <= 0:
        return 0
    return min(selected_count, affordable_waves * worker_count)


def parse_speed_bands(text: str) -> list[tuple[int, int]]:
    bands: list[tuple[int, int]] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"invalid speed band: {part}")
        size_text, take_text = part.split(":", 1)
        size = int(size_text)
        take = int(take_text)
        if size <= 0 or take < 0:
            raise ValueError(f"invalid speed band: {part}")
        bands.append((size, take))
    return bands or [(100, 50), (100, 30), (100, 20)]


def parse_country_min(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for part in str(text or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"invalid preferred country minimum: {part}")
        code, value = part.split(":", 1)
        code = code.strip().upper()
        if not code:
            raise ValueError(f"invalid preferred country minimum: {part}")
        count = int(value)
        if count < 0:
            raise ValueError(f"invalid preferred country minimum: {part}")
        result[code] = count
    return result


def parse_geo_providers(text: str) -> list[str]:
    value = str(text or "daily").strip().lower()
    if value == "all":
        return list(DEFAULT_GEO_PROVIDERS_ALL)
    if value == "daily":
        return list(DEFAULT_GEO_PROVIDERS_DAILY)
    providers: list[str] = []
    for part in value.split(","):
        provider = part.strip().lower().replace("-", "_")
        if not provider:
            continue
        if provider not in GEO_PROVIDER_URLS:
            valid = ",".join(sorted(GEO_PROVIDER_URLS))
            raise ValueError(f"invalid geo provider: {provider}; valid: daily,all,{valid}")
        providers.append(provider)
    return providers or list(DEFAULT_GEO_PROVIDERS_DAILY)


def profile_defaults(profile: str) -> dict[str, Any]:
    profiles: dict[str, dict[str, Any]] = {
        "fast": {
            "source_timeout": 8,
            "source_retries": 0,
            "source_concurrency": 12,
            "latency_threshold": 800,
            "geo_providers": "daily",
            "time_budget": 180,
            "time_safety_margin": 20,
            "latency_pool_limit": 120,
            "max_final_candidates": 180,
            "country_max": 0,
            "final_preferred_latency_ms": 800,
            "geo_initial_limit": 200,
            "geo_refill_batch_size": 50,
            "geo_refill_min_batch_size": 20,
            "geo_refill_max_tested": 300,
            "preferred_country_min": "JP:10,SG:15,HK:15,US:5,KR:2,TW:2",
            "geo_concurrency": 8,
            "speed_limit": 0,
            "speed_bands": "100:20",
            "speed_concurrency": 4,
            "speed_timeout": 6,
            "service_timeout": 5,
            "min_service_score": 2,
            "min_download_bytes": 512 * 1024,
            "speed_urls": list(DEFAULT_LIGHT_SPEED_URLS),
        },
        "balanced": {
            "source_timeout": 8,
            "source_retries": 0,
            "source_concurrency": 12,
            "latency_threshold": 800,
            "geo_providers": "daily",
            "time_budget": 0,
            "time_safety_margin": 0,
            "latency_pool_limit": 0,
            "max_final_candidates": 300,
            "country_max": 50,
            "final_preferred_latency_ms": 800,
            "geo_initial_limit": 0,
            "geo_refill_batch_size": 75,
            "geo_refill_min_batch_size": 20,
            "geo_refill_max_tested": 0,
            "preferred_country_min": "JP:20,SG:30,HK:30,US:10,KR:3,TW:3",
            "geo_concurrency": 8,
            "speed_limit": 0,
            "speed_bands": "100:30",
            "speed_concurrency": 4,
            "speed_timeout": 8,
            "service_timeout": 6,
            "min_service_score": 2,
            "min_download_bytes": 512 * 1024,
            "speed_urls": list(DEFAULT_LIGHT_SPEED_URLS),
        },
        "full": {
            "source_timeout": 20,
            "source_retries": 2,
            "source_concurrency": 6,
            "latency_threshold": 1000,
            "geo_providers": "daily",
            "time_budget": 0,
            "time_safety_margin": 0,
            "latency_pool_limit": 0,
            "max_final_candidates": 0,
            "country_max": 0,
            "final_preferred_latency_ms": 800,
            "geo_initial_limit": 0,
            "geo_refill_batch_size": 100,
            "geo_refill_min_batch_size": 1,
            "geo_refill_max_tested": 0,
            "preferred_country_min": "JP:20,SG:30,HK:30,US:10,KR:3,TW:3",
            "geo_concurrency": 4,
            "speed_limit": 100,
            "speed_bands": "100:50,100:30,100:20",
            "speed_concurrency": 2,
            "speed_timeout": 15,
            "service_timeout": 8,
            "min_service_score": 2,
            "min_download_bytes": 1024 * 1024,
            "speed_urls": list(DEFAULT_SPEED_URLS),
        },
    }
    return profiles.get(profile, profiles["balanced"])


def apply_profile_defaults(args: argparse.Namespace) -> None:
    defaults = profile_defaults(args.profile)
    for name in [
        "source_timeout",
        "source_retries",
        "source_concurrency",
        "latency_threshold",
        "geo_providers",
        "time_budget",
        "time_safety_margin",
        "latency_pool_limit",
        "max_final_candidates",
        "country_max",
        "final_preferred_latency_ms",
        "geo_initial_limit",
        "geo_refill_batch_size",
        "geo_refill_min_batch_size",
        "geo_refill_max_tested",
        "preferred_country_min",
        "geo_concurrency",
        "speed_limit",
        "speed_bands",
        "speed_concurrency",
        "speed_timeout",
        "service_timeout",
        "min_service_score",
        "min_download_bytes",
    ]:
        if getattr(args, name) is None:
            setattr(args, name, defaults[name])
    if args.speed_url is None:
        args.speed_urls = list(defaults["speed_urls"])
    else:
        args.speed_urls = list(args.speed_url)


def preferred_counts(results: list[TestResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results:
        code = (result.exit_country_code or "").upper()
        if not code:
            continue
        counts[code] = counts.get(code, 0) + 1
    return counts


def candidate_mentions_country(candidate: Candidate, code: str) -> bool:
    code = code.upper()
    names = {country_name(code)}
    aliases = {alias for alias, name in REGION_ALIASES.items() if name in names}
    declared = (candidate.declared_region or "").upper()
    if declared == code or candidate.declared_region in names:
        return True
    text = f"{candidate.source} {candidate.name} {candidate.raw}".upper()
    if re.search(rf"(?<![A-Z]){re.escape(code)}(?![A-Z])", text):
        return True
    return any(re.search(rf"(?<![A-Z]){re.escape(alias)}(?![A-Z])", text) for alias in aliases)


def take_country_targeted_candidates(
    eligible: list[tuple[str, Candidate, int]],
    cursor: int,
    code: str,
    limit: int,
) -> list[tuple[str, Candidate, int]]:
    if limit <= 0:
        return []
    taken: list[tuple[str, Candidate, int]] = []
    index = cursor
    while index < len(eligible) and len(taken) < limit:
        item = eligible[index]
        if candidate_mentions_country(item[1], code):
            taken.append(item)
            del eligible[index]
            continue
        index += 1
    return taken


def refill_budget_remaining(args: argparse.Namespace) -> float:
    if args.time_budget <= 0:
        return float("inf")
    elapsed = time.monotonic() - args.run_started_at
    return args.time_budget - elapsed - max(0, args.time_safety_margin)


def run_geo_batch(
    items: list[tuple[str, Candidate, int]],
    template_proxy: dict[str, Any],
    args: argparse.Namespace,
    stage: str,
) -> list[TestResult]:
    if not items:
        return []
    stage_started = time.monotonic()
    geo_chunks = split_evenly(items, args.geo_concurrency)
    geo_results: list[TestResult] = []
    with ThreadPoolExecutor(max_workers=args.geo_concurrency) as pool:
        futures = [
            pool.submit(test_geo_chunk, chunk, template_proxy, worker_id, args)
            for worker_id, chunk in enumerate(geo_chunks)
            if chunk
        ]
        done = 0
        total = len(items)
        for future in as_completed(futures):
            chunk_results = [dataclasses.replace(result, selection_stage=stage) for result in future.result()]
            geo_results.extend(chunk_results)
            done += len(chunk_results)
            ok_count = sum(1 for result in geo_results if result.ok)
            print(f"[geo-{stage} {done}/{total}] preferred={ok_count}", flush=True)
    elapsed = time.monotonic() - stage_started
    key = f"geo_{stage}_test"
    args.timings[key] = args.timings.get(key, 0.0) + elapsed
    args.timings["geo_test"] = args.timings.get("geo_test", 0.0) + elapsed
    return geo_results


def adaptive_refill_batch_size(args: argparse.Namespace, geo_tested: int) -> int:
    remaining_budget = refill_budget_remaining(args)
    if remaining_budget == float("inf"):
        return args.geo_refill_batch_size
    if remaining_budget <= 0:
        return 0
    avg_geo_cost = args.timings.get("geo_test", 0.0) / max(1, geo_tested)
    avg_geo_cost = max(avg_geo_cost, 0.05)
    return min(args.geo_refill_batch_size, int(remaining_budget / avg_geo_cost))


def run_latency_first_tests(
    candidates: list[Candidate],
    template_proxy: dict[str, Any],
    args: argparse.Namespace,
) -> list[TestResult]:
    stage_started = time.monotonic()
    eligible, latency_failures = run_latency_tests(candidates, template_proxy, args)
    args.timings["latency_test"] = time.monotonic() - stage_started
    print(f"Latency passed: {len(eligible)} / {len(candidates)}", flush=True)

    initial_limit = len(eligible) if args.geo_initial_limit <= 0 else min(args.geo_initial_limit, len(eligible))
    cursor = initial_limit
    selected = eligible[:initial_limit]
    print(f"Geo initial selected: {len(selected)}", flush=True)

    geo_results = run_geo_batch(selected, template_proxy, args, "initial")
    geo_tested = len(selected)
    preferred_geo = sort_geo_results([result for result in geo_results if result.ok], args.preferred_country_order)
    print(f"Geo initial preferred: {len(preferred_geo)}", flush=True)

    target_total = args.latency_pool_limit
    max_geo_tested = args.geo_refill_max_tested
    refill_stop_reason = ""

    for code in args.preferred_country_min:
        counts = preferred_counts(preferred_geo)
        if counts.get(code, 0) >= args.preferred_country_min[code]:
            continue
        if cursor >= len(eligible):
            break
        if max_geo_tested > 0 and geo_tested >= max_geo_tested:
            break
        batch_size = adaptive_refill_batch_size(args, geo_tested)
        if batch_size < args.geo_refill_min_batch_size:
            break
        if max_geo_tested > 0:
            batch_size = min(batch_size, max_geo_tested - geo_tested)
        batch_size = min(batch_size, args.geo_refill_batch_size, len(eligible) - cursor)
        targeted = take_country_targeted_candidates(eligible, cursor, code, batch_size)
        if not targeted:
            continue
        before_country = counts.get(code, 0)
        before_total = len(preferred_geo)
        batch_results = run_geo_batch(targeted, template_proxy, args, f"target_{code.lower()}")
        geo_tested += len(targeted)
        geo_results.extend(batch_results)
        preferred_geo = sort_geo_results([result for result in geo_results if result.ok], args.preferred_country_order)
        counts = preferred_counts(preferred_geo)
        print(
            f"[geo-target-refill] country={code}; tested={len(targeted)}; "
            f"country_added={counts.get(code, 0) - before_country}; "
            f"preferred_added={len(preferred_geo) - before_total}; "
            f"current={counts.get(code, 0)}/{args.preferred_country_min[code]}; "
            f"preferred_total={len(preferred_geo)}; remaining_budget={refill_budget_remaining(args):.1f}s",
            flush=True,
        )

    while cursor < len(eligible):
        if target_total > 0 and len(preferred_geo) >= target_total:
            refill_stop_reason = f"target reached {len(preferred_geo)}/{target_total}"
            break
        if max_geo_tested > 0 and geo_tested >= max_geo_tested:
            refill_stop_reason = f"geo_refill_max_tested reached {geo_tested}/{max_geo_tested}"
            break
        batch_size = adaptive_refill_batch_size(args, geo_tested)
        if batch_size < args.geo_refill_min_batch_size:
            refill_stop_reason = (
                f"time budget reserved; batch_size={batch_size}; "
                f"remaining_budget={refill_budget_remaining(args):.1f}s"
            )
            break
        if max_geo_tested > 0:
            batch_size = min(batch_size, max_geo_tested - geo_tested)
        batch_size = min(batch_size, len(eligible) - cursor)
        if batch_size <= 0:
            refill_stop_reason = "no refill candidates"
            break
        batch = eligible[cursor : cursor + batch_size]
        cursor += batch_size
        before = len(preferred_geo)
        batch_results = run_geo_batch(batch, template_proxy, args, "refill")
        geo_tested += len(batch)
        geo_results.extend(batch_results)
        preferred_geo = sort_geo_results([result for result in geo_results if result.ok], args.preferred_country_order)
        print(
            f"[geo-refill-summary] tested={geo_tested}; "
            f"preferred_added={len(preferred_geo) - before}; preferred_total={len(preferred_geo)}; "
            f"remaining_budget={refill_budget_remaining(args):.1f}s",
            flush=True,
        )
    else:
        refill_stop_reason = "latency candidates exhausted"

    country_refill_started = False
    for code in args.preferred_country_min:
        counts = preferred_counts(preferred_geo)
        if counts.get(code, 0) >= args.preferred_country_min[code]:
            continue
        if cursor >= len(eligible):
            break
        if max_geo_tested > 0 and geo_tested >= max_geo_tested:
            break
        while counts.get(code, 0) < args.preferred_country_min[code] and cursor < len(eligible):
            if max_geo_tested > 0 and geo_tested >= max_geo_tested:
                break
            batch_size = adaptive_refill_batch_size(args, geo_tested)
            if batch_size < args.geo_refill_min_batch_size:
                break
            if max_geo_tested > 0:
                batch_size = min(batch_size, max_geo_tested - geo_tested)
            batch_size = min(batch_size, len(eligible) - cursor)
            if batch_size <= 0:
                break
            country_refill_started = True
            batch = eligible[cursor : cursor + batch_size]
            cursor += batch_size
            before_country = counts.get(code, 0)
            batch_results = run_geo_batch(batch, template_proxy, args, "country_refill")
            geo_tested += len(batch)
            geo_results.extend(batch_results)
            preferred_geo = sort_geo_results([result for result in geo_results if result.ok], args.preferred_country_order)
            counts = preferred_counts(preferred_geo)
            print(
                f"[geo-country-refill] country={code}; added={counts.get(code, 0) - before_country}; "
                f"current={counts.get(code, 0)}/{args.preferred_country_min[code]}; "
                f"preferred_total={len(preferred_geo)}; remaining_budget={refill_budget_remaining(args):.1f}s",
                flush=True,
            )

    if not country_refill_started:
        args.timings.setdefault("geo_country_refill_test", 0.0)
    preferred_geo_all = sort_geo_results([result for result in geo_results if result.ok], args.preferred_country_order)
    preferred_geo = preferred_geo_all
    skipped_latency_pool = eligible[cursor:]
    latency_failures.extend(
        TestResult(
            candidate,
            False,
            "latency_pool_skipped",
            refill_stop_reason or "not selected for geo",
            latency_ms=float(delay),
        )
        for _proxy_name, candidate, delay in skipped_latency_pool
    )
    print(f"Geo tested: {geo_tested}; stop reason: {refill_stop_reason}", flush=True)
    print(f"Preferred geo selected: {len(preferred_geo)} / {len(preferred_geo_all)}", flush=True)
    speed_keys = select_speed_sample(preferred_geo, args.speed_bands_parsed, args.speed_limit)
    speed_selected = [result for result in preferred_geo if result.candidate.key in speed_keys]
    geo_only = [result for result in preferred_geo if result.candidate.key not in speed_keys]
    speed_budget_limit = budgeted_speed_sample_limit(args, len(speed_selected))
    if speed_budget_limit < len(speed_selected):
        skipped_speed = speed_selected[speed_budget_limit:]
        speed_selected = speed_selected[:speed_budget_limit]
        geo_only.extend(
            dataclasses.replace(result, ok=True, status="geo_only", error="speed skipped by time budget")
            for result in skipped_speed
        )
        print(
            f"Speed sample reduced by time budget: {len(skipped_speed)} skipped; "
            f"remaining_budget={speed_budget_remaining(args):.1f}s",
            flush=True,
        )
    print(f"Selected for speed: {len(speed_selected)}; geo-only: {len(geo_only)}", flush=True)

    stage_started = time.monotonic()
    speed_chunks = split_evenly(speed_selected, args.speed_concurrency)
    speed_results: list[TestResult] = []
    with ThreadPoolExecutor(max_workers=args.speed_concurrency) as pool:
        futures = [
            pool.submit(test_speed_chunk_from_geo, chunk, template_proxy, worker_id, args)
            for worker_id, chunk in enumerate(speed_chunks)
            if chunk
        ]
        done = 0
        total = len(speed_selected)
        for future in as_completed(futures):
            chunk_results = future.result()
            speed_results.extend(chunk_results)
            done += len(chunk_results)
            speed_count = sum(1 for result in speed_results if result.measured_speed is not None)
            print(f"[speed {done}/{total}] speed_ok={speed_count}", flush=True)
    args.timings["speed_test"] = time.monotonic() - stage_started
    return latency_failures + [result for result in geo_results if not result.ok] + geo_only + speed_results


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BestCF rebinder/tester")
    parser.add_argument(
        "--profile",
        choices=["fast", "balanced", "full"],
        default="balanced",
        help="runtime profile; balanced is optimized for Clash Verge daily use",
    )
    parser.add_argument("--workdir", default=str(DEFAULT_WORKDIR), help="work directory")
    parser.add_argument("--template", default=str(DEFAULT_TEMPLATE), help="Clash/Mihomo YAML template")
    parser.add_argument("--template-name", default=None, help="specific proxy name to use as template")
    parser.add_argument("--mihomo", default=str(DEFAULT_MIHOMO), help="mihomo executable path")
    parser.add_argument("--output", default=None, help="final txt output path")
    parser.add_argument("--timeout", type=int, default=12, help="geo request timeout")
    parser.add_argument("--speed-timeout", type=int, default=None, help="speed test timeout")
    parser.add_argument("--source-timeout", type=int, default=None, help="source fetch timeout")
    parser.add_argument("--source-retries", type=int, default=None, help="retry count for failed source downloads")
    parser.add_argument("--source-concurrency", type=int, default=None, help="parallel source download workers")
    parser.add_argument("--start-timeout", type=float, default=6.0, help="mihomo startup timeout")
    parser.add_argument("--concurrency", type=int, default=4, help="parallel test workers")
    parser.add_argument("--legacy-per-candidate", action="store_true", help="use old per-candidate mihomo process mode")
    parser.add_argument("--no-discover-sources", action="store_true", help="disable bestcf.pages.dev source discovery")
    parser.add_argument("--latency-url", default=DEFAULT_LATENCY_URL, help="URL used by Mihomo delay API")
    parser.add_argument("--latency-timeout", type=int, default=5000, help="Mihomo delay timeout in milliseconds")
    parser.add_argument("--latency-threshold", type=int, default=None, help="max delay in ms before geo pool")
    parser.add_argument("--geo-providers", default=None, help="geo providers: daily, all, or comma-separated names")
    parser.add_argument("--geo-cache", default=None, help="geo cache path")
    parser.add_argument("--geo-cache-ttl-hours", type=float, default=12.0, help="hours before geo cache entries expire")
    parser.add_argument("--no-geo-cache", dest="geo_cache_enabled", action="store_false", help="disable geo cache read/write")
    parser.set_defaults(geo_cache_enabled=True)
    parser.add_argument("--time-budget", type=float, default=None, help="target end-to-end runtime budget in seconds; 0 disables")
    parser.add_argument("--time-safety-margin", type=float, default=None, help="seconds reserved before time budget for speed/write cleanup")
    parser.add_argument("--latency-pool-limit", type=int, default=None, help="target number of preferred geo candidates; 0 disables target")
    parser.add_argument("--max-final-candidates", type=int, default=None, help="maximum preferred candidates written to final output; 0 disables")
    parser.add_argument("--country-max", type=int, default=None, help="maximum final output candidates per exit country; 0 disables")
    parser.add_argument("--final-preferred-latency-ms", type=int, default=None, help="scarce regions prefer nodes no slower than this latency")
    parser.add_argument("--geo-initial-limit", type=int, default=None, help="initial latency-ranked candidates selected for geo; 0 means all")
    parser.add_argument("--geo-refill-batch-size", type=int, default=None, help="candidate count per geo refill batch")
    parser.add_argument("--geo-refill-min-batch-size", type=int, default=None, help="stop refill when time budget allows fewer than this batch size")
    parser.add_argument("--geo-refill-max-tested", type=int, default=None, help="maximum geo-tested latency candidates including initial batch; 0 disables")
    parser.add_argument("--latency-concurrency", type=int, default=32, help="parallel Mihomo delay API calls")
    parser.add_argument("--geo-concurrency", type=int, default=None, help="parallel geo workers after latency pool selection")
    parser.add_argument("--speed-limit", type=int, default=None, help="maximum number of candidates selected for speed test; 0 disables speed test")
    parser.add_argument("--speed-bands", default=None, help="latency ranked band sampling, e.g. 100:50,100:30,100:20")
    parser.add_argument("--speed-concurrency", type=int, default=None, help="parallel all-in-one speed workers")
    parser.add_argument(
        "--preferred-countries",
        default="JP,SG,US,HK,KR,TW",
        help="comma-separated exit country codes kept by default, order matters",
    )
    parser.add_argument(
        "--preferred-country-min",
        default=None,
        help="minimum preferred output by country, e.g. JP:20,SG:30,HK:30,US:10,KR:3,TW:3",
    )
    parser.add_argument("--allow-other-regions", dest="allow_other_regions", action="store_true", help="do not filter non-preferred exit countries")
    parser.add_argument("--preferred-regions-only", dest="allow_other_regions", action="store_false", help="filter non-preferred exit countries")
    parser.set_defaults(allow_other_regions=True)
    parser.add_argument("--allow-unknown-region", action="store_true", help="allow speed test when exit country is unknown")
    parser.add_argument("--no-service-check", dest="service_check", action="store_false", help="disable Google/YouTube/GPT reachability checks")
    parser.set_defaults(service_check=True)
    parser.add_argument("--service-timeout", type=int, default=None, help="service reachability check timeout in seconds")
    parser.add_argument("--min-service-score", type=int, default=None, help="minimum passed service checks among Google/YouTube/GPT")
    parser.add_argument("--google-url", default=DEFAULT_SERVICE_URLS["google"], help="Google reachability probe URL")
    parser.add_argument("--youtube-url", default=DEFAULT_SERVICE_URLS["youtube"], help="YouTube reachability probe URL")
    parser.add_argument("--gpt-url", default=DEFAULT_SERVICE_URLS["gpt"], help="GPT reachability probe URL")
    parser.add_argument("--verbose-services", action="store_true", help="record successful service probe details")
    parser.add_argument("--limit", type=int, default=0, help="test only first N candidates after pre-sort")
    parser.add_argument("--top", type=int, default=0, help="write only top N successful lines")
    parser.add_argument("--min-speed", type=float, default=0.01, help="minimum measured MB/s")
    parser.add_argument(
        "--speed-url",
        action="append",
        default=None,
        help="download URL for speed test; can be provided multiple times",
    )
    parser.add_argument("--min-download-bytes", type=int, default=None, help="minimum bytes required for valid speed test")
    parser.add_argument("--base-port", type=int, default=17897, help="first mixed proxy port")
    parser.add_argument("--controller-base-port", type=int, default=19097, help="first controller port")
    parser.add_argument("--dry-run", action="store_true", help="fetch and parse only; do not start mihomo")
    parser.add_argument("--keep-workers", action="store_true", help="do not delete previous worker dirs before running")
    parser.add_argument(
        "--source-denylist",
        default=None,
        help="hard source denylist path; entries are removed before download",
    )
    parser.add_argument(
        "--no-auto-prune-sources",
        action="store_true",
        help="do not add zero-valid nonempty sources to the hard denylist",
    )
    parser.add_argument(
        "--source-prune-min-lines",
        type=int,
        default=DEFAULT_SOURCE_PRUNE_MIN_LINES,
        help="minimum nonempty lines before a zero-valid source can be auto-pruned",
    )
    parser.add_argument(
        "--source-high-invalid-ratio",
        type=float,
        default=DEFAULT_SOURCE_HIGH_INVALID_RATIO,
        help="write review warning when a source has valid candidates but invalid ratio is at least this value",
    )
    parser.add_argument(
        "--use-source-cache-quarantine",
        action="store_true",
        help="also use the legacy cached invalid-source quarantine before download",
    )
    parser.add_argument(
        "--refresh-sources",
        action="store_true",
        help="ignore hard denylist and cached invalid-source quarantine, then re-check every source",
    )
    parser.add_argument(
        "--source-invalid-threshold",
        type=int,
        default=DEFAULT_SOURCE_INVALID_THRESHOLD,
        help="quarantine a source after N successful fetches with zero parseable candidates",
    )
    parser.add_argument(
        "--source-quarantine-hours",
        type=float,
        default=DEFAULT_SOURCE_QUARANTINE_HOURS,
        help="hours to skip a quarantined invalid source before re-checking it",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    timer = StageTimer()
    args = build_arg_parser().parse_args(argv)
    apply_profile_defaults(args)
    args.concurrency = max(1, args.concurrency)
    args.source_concurrency = max(1, args.source_concurrency)
    args.source_retries = max(0, args.source_retries)
    args.latency_concurrency = max(1, args.latency_concurrency)
    args.geo_concurrency = max(1, args.geo_concurrency)
    args.geo_providers_resolved = parse_geo_providers(args.geo_providers)
    args.geo_cache_ttl_hours = max(0.0, float(args.geo_cache_ttl_hours))
    args.speed_concurrency = max(1, args.speed_concurrency)
    args.speed_bands_parsed = parse_speed_bands(args.speed_bands)
    args.min_service_score = max(0, min(3, args.min_service_score))
    args.time_budget = max(0.0, float(args.time_budget))
    args.time_safety_margin = max(0.0, float(args.time_safety_margin))
    args.latency_pool_limit = max(0, int(args.latency_pool_limit))
    args.max_final_candidates = max(0, int(args.max_final_candidates))
    args.country_max = max(0, int(args.country_max))
    args.final_preferred_latency_ms = max(0, int(args.final_preferred_latency_ms))
    args.geo_initial_limit = max(0, int(args.geo_initial_limit))
    args.geo_refill_batch_size = max(1, int(args.geo_refill_batch_size))
    args.geo_refill_min_batch_size = max(1, int(args.geo_refill_min_batch_size))
    args.geo_refill_max_tested = max(0, int(args.geo_refill_max_tested))
    args.preferred_country_min = parse_country_min(args.preferred_country_min)
    args.timings = timer.timings
    args.run_started_at = timer.started_at
    args.preferred_country_order = [
        item.strip().upper()
        for item in str(args.preferred_countries).split(",")
        if item.strip()
    ] or list(PREFERRED_COUNTRY_ORDER)
    args.preferred_countries = set(args.preferred_country_order)
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    args.geo_cache_path = Path(args.geo_cache) if args.geo_cache else workdir / DEFAULT_GEO_CACHE_NAME
    args.geo_cache = load_geo_cache(args.geo_cache_path) if args.geo_cache_enabled else {"version": GEO_CACHE_VERSION, "entries": {}}
    args.geo_cache_lock = threading.Lock()
    if not args.keep_workers:
        clean_workers(workdir)
    timer.mark("setup")

    print("Fetching sources...", flush=True)
    source_cache_path = workdir / DEFAULT_SOURCE_CACHE_NAME
    source_cache = load_source_cache(source_cache_path)
    sources = build_sources(
        discover=not args.no_discover_sources,
        timeout=args.source_timeout,
        source_cache=source_cache,
    )
    source_denylist_path = Path(args.source_denylist) if args.source_denylist else workdir / DEFAULT_SOURCE_DENYLIST_NAME
    source_denylist = set() if args.refresh_sources else load_source_denylist(source_denylist_path)
    sources_after_denylist, denied_source_failures = filter_denied_sources(sources, source_denylist)
    if args.use_source_cache_quarantine:
        active_sources, skipped_cached_failures = filter_cached_invalid_sources(
            sources_after_denylist,
            source_cache,
            refresh=args.refresh_sources,
        )
    else:
        active_sources, skipped_cached_failures = dict(sources_after_denylist), []
    print(
        "Source count: "
        f"{len(sources)}; active: {len(active_sources)}; "
        f"hard-pruned: {len(denied_source_failures)}; "
        f"cached-skipped: {len(skipped_cached_failures)}",
        flush=True,
    )
    rows, fetch_failures = fetch_sources(
        active_sources,
        timeout=args.source_timeout,
        concurrency=args.source_concurrency,
        retries=args.source_retries,
    )
    source_failures = denied_source_failures + skipped_cached_failures + fetch_failures
    write_raw(workdir, rows)
    candidates, parse_failures, source_stats = parse_candidates(rows, active_sources)
    write_parsed(workdir, candidates)
    newly_denied: set[str] = set()
    if not args.no_auto_prune_sources and not args.refresh_sources:
        newly_denied = update_source_denylist_from_stats(
            source_denylist_path,
            source_denylist,
            active_sources,
            source_stats,
            source_failures,
            min_lines=args.source_prune_min_lines,
            high_invalid_ratio=args.source_high_invalid_ratio,
        )
    update_source_cache(
        source_cache,
        active_sources,
        source_stats,
        source_failures,
        invalid_threshold=args.source_invalid_threshold,
        quarantine_hours=args.source_quarantine_hours,
    )
    save_source_cache(source_cache_path, source_cache)
    write_source_report(workdir, sources, source_stats, source_failures, source_cache)
    write_source_prune_report(
        workdir,
        sources,
        source_stats,
        source_failures,
        source_denylist | newly_denied,
        newly_denied,
        min_lines=args.source_prune_min_lines,
        high_invalid_ratio=args.source_high_invalid_ratio,
    )
    total_unique = len(candidates)
    if args.limit > 0:
        candidates = candidates[: args.limit]

    print(f"Fetched lines: {len(rows)}", flush=True)
    print(f"Parsed unique candidates: {total_unique}; selected for test: {len(candidates)}", flush=True)
    actual_fetch_failures = sum(1 for failure in source_failures if failure.get("status") == "source_fetch_failed")
    print(
        "Source status: "
        f"fetch_failed={actual_fetch_failures}; "
        f"hard_pruned={len(denied_source_failures)}; "
        f"cached_skipped={len(skipped_cached_failures)}; "
        f"parse_failed_lines={len(parse_failures)}",
        flush=True,
    )
    print(f"Source report: {workdir / 'bestcf_sources.csv'}", flush=True)
    print(f"Source prune report: {workdir / DEFAULT_SOURCE_PRUNE_REPORT_NAME}", flush=True)
    if newly_denied:
        print(f"New hard-pruned sources for next run: {len(newly_denied)}", flush=True)
    timer.mark("source_fetch_parse")

    if args.dry_run:
        final = write_results(workdir, [], parse_failures, source_failures, args)
        if args.output:
            shutil.copyfile(final, args.output)
        print(f"Dry-run completed. Parsed CSV: {workdir / 'bestcf_parsed.csv'}", flush=True)
        print(timer.summary(), flush=True)
        return 0

    template_path = Path(args.template)
    mihomo_path = Path(args.mihomo)
    if not template_path.exists():
        raise FileNotFoundError(template_path)
    if not mihomo_path.exists():
        raise FileNotFoundError(mihomo_path)
    template_proxy = load_template(template_path, template_name=args.template_name)
    print(
        "Selected template: "
        f"name={template_proxy.get('name')} type={template_proxy.get('type')} network={template_proxy.get('network')}",
        flush=True,
    )
    timer.mark("template_load")

    if args.legacy_per_candidate:
        stage_started = time.monotonic()
        results = run_tests(candidates, template_proxy, args)
        args.timings["legacy_test"] = time.monotonic() - stage_started
    else:
        results = run_latency_first_tests(candidates, template_proxy, args)
    if args.top > 0:
        ok = [item for item in results if item.ok and item.measured_speed is not None]
        ok.sort(key=lambda item: -(item.measured_speed or 0))
        allowed = {id(item) for item in ok[: args.top]}
        results = [item for item in results if not item.ok or id(item) in allowed]
    stage_started = time.monotonic()
    final = write_results(workdir, results, parse_failures, source_failures, args)
    if args.output:
        shutil.copyfile(final, args.output)
        final = Path(args.output)
    if args.geo_cache_enabled:
        save_geo_cache(args.geo_cache_path, args.geo_cache)
    args.timings["write_results"] = time.monotonic() - stage_started
    print(f"Final output: {final}", flush=True)
    print(f"Successful: {sum(1 for result in results if result.ok)}; failed: {sum(1 for result in results if not result.ok)}", flush=True)
    print(timer.summary(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
