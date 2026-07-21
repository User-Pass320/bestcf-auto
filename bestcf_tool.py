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
import hashlib
import http.client
import ipaddress
import json
import locale
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
DEFAULT_GEO_HINT_CACHE_NAME = "bestcf_geo_hint_cache.json"
DEFAULT_SOURCE_DENYLIST_NAME = "bestcf_source_denylist.txt"
DEFAULT_SOURCE_PRUNE_REPORT_NAME = "bestcf_source_prune_candidates.csv"
DEFAULT_CFST_EXE_WINDOWS = Path(r".\tools\cfst\cfst.exe")
DEFAULT_CFST_IP_FILE = Path(r".\tools\cfst\ip.txt")
SOURCE_CACHE_VERSION = 1
GEO_CACHE_VERSION = 3
GEO_HINT_CACHE_VERSION = 1
DEFAULT_GEO_POLICY_VERSION = "youtube_primary_ping0_ipwhois_fallback_v1"
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
GEO_HINT_PROMOTE_COUNTRY_ORDER = ["JP", "KR", "TW", "US"]
PREFERRED_REGION_NAMES = {"香港", "日本", "新加坡", "美国", "韩国", "台湾"}
DEFAULT_LATENCY_URL = "https://www.gstatic.com/generate_204"
GEO_PROVIDER_URLS = {
    "youtube": "https://www.youtube.com/",
    "ipinfo": "https://ipinfo.io/json",
    "ip_sb": "https://api.ip.sb/geoip",
    "cloudflare": "https://www.cloudflare.com/cdn-cgi/trace",
    "ping0": "https://ip.ping0.cc/geo",
    "ipapi": "https://ipapi.co/json/",
    "ipwhois": "https://ipwho.is/",
    "ip_api": "http://ip-api.com/json/?fields=status,countryCode,query",
}
DEFAULT_GEO_PROVIDERS_DAILY = ["youtube", "ping0", "ipwhois"]
DEFAULT_GEO_PROVIDERS_ALL = ["youtube", "ping0", "ipwhois", "ip_api", "ipinfo", "ip_sb", "cloudflare", "ipapi"]
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
    "CN": "中国",
    "HK": "香港",
    "JP": "日本",
    "SG": "新加坡",
    "US": "美国",
    "KR": "韩国",
    "TW": "台湾",
    "MO": "澳门",
    "DE": "德国",
    "GB": "英国",
    "UK": "英国",
    "FR": "法国",
    "NL": "荷兰",
    "CA": "加拿大",
    "AU": "澳大利亚",
    "TH": "泰国",
    "VN": "越南",
    "ES": "西班牙",
    "PT": "葡萄牙",
    "CH": "瑞士",
    "QA": "卡塔尔",
    "DK": "丹麦",
    "SE": "瑞典",
    "AT": "奥地利",
    "BG": "保加利亚",
    "CZ": "捷克",
    "IT": "意大利",
    "NO": "挪威",
    "RO": "罗马尼亚",
    "MY": "马来西亚",
    "ID": "印度尼西亚",
    "PH": "菲律宾",
    "IN": "印度",
    "IE": "爱尔兰",
    "PL": "波兰",
    "RS": "塞尔维亚",
    "SA": "沙特阿拉伯",
}

SPECIFIC_REGION_CODES = {
    "香港": "HK",
    "台湾": "TW",
    "澳门": "MO",
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

CFST_COLO_COUNTRY = {
    "HKG": "HK",
    "SIN": "SG",
    "NRT": "JP",
    "KIX": "JP",
    "TPE": "TW",
    "ICN": "KR",
    "LAX": "US",
    "SJC": "US",
    "SEA": "US",
    "PDX": "US",
    "DEN": "US",
    "FRA": "DE",
    "MRS": "FR",
    "LYS": "FR",
    "CPH": "DK",
}

CFST_COUNTRY_POOL_DEFAULTS = {
    "HK": 60,
    "SG": 60,
    "UNKNOWN": 0,  # 0 means all candidates in the bucket.
}


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
    geo_policy: str = DEFAULT_GEO_POLICY_VERSION
    geo_selected_provider: str = ""
    geo_fallback_used: bool = False
    geo_hint_country: str = ""
    geo_hint_source: str = ""
    geo_cache_status: str = ""
    service_score: int = 0
    google_ok: bool | None = None
    youtube_ok: bool | None = None
    gpt_ok: bool | None = None
    service_error: str = ""
    selection_stage: str = ""


@dataclasses.dataclass(slots=True)
class GeoDecision:
    country_code: str | None
    region: str
    exit_ip: str | None
    cf_colo: str | None
    evidence: str
    policy: str = DEFAULT_GEO_POLICY_VERSION
    selected_provider: str = ""
    fallback_used: bool = False


@dataclasses.dataclass(slots=True)
class HkSuppressionDecision:
    suppress: bool
    bucket_key: str = ""
    reason: str = ""
    total: int = 0
    hk: int = 0


def geo_result_fields(geo: GeoDecision) -> dict[str, Any]:
    return {
        "exit_ip": geo.exit_ip,
        "exit_country_code": geo.country_code,
        "exit_region": geo.region,
        "cf_colo": geo.cf_colo,
        "geo_evidence": geo.evidence,
        "geo_policy": geo.policy,
        "geo_selected_provider": geo.selected_provider,
        "geo_fallback_used": geo.fallback_used,
    }


def geo_hint_fields(candidate: Candidate, args: argparse.Namespace) -> dict[str, str]:
    country, source = candidate_geo_hint(candidate, args)
    return {"geo_hint_country": country, "geo_hint_source": source}


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
    for name, code in SPECIFIC_REGION_CODES.items():
        if name in text:
            return code
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
    if data.get("version") != GEO_CACHE_VERSION:
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


def ip_prefix_for_hint(host: str) -> str | None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.version == 4:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
    else:
        network = ipaddress.ip_network(f"{ip}/48", strict=False)
    return str(network)


def ip_prefix_for_runtime_suppression(host: str, ipv4_bits: int = 16, ipv6_bits: int = 32) -> str | None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    bits = int(ipv4_bits if ip.version == 4 else ipv6_bits)
    max_bits = 32 if ip.version == 4 else 128
    bits = max(0, min(max_bits, bits))
    return str(ipaddress.ip_network(f"{ip}/{bits}", strict=False))


def empty_geo_hint_cache() -> dict[str, Any]:
    return {"version": GEO_HINT_CACHE_VERSION, "hosts": {}, "prefixes": {}}


def load_geo_hint_cache(path: Path) -> dict[str, Any]:
    if not path.exists():
        return empty_geo_hint_cache()
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return empty_geo_hint_cache()
    if not isinstance(data, dict) or data.get("version") != GEO_HINT_CACHE_VERSION:
        return empty_geo_hint_cache()
    if not isinstance(data.get("hosts"), dict):
        data["hosts"] = {}
    if not isinstance(data.get("prefixes"), dict):
        data["prefixes"] = {}
    return data


def save_geo_hint_cache(path: Path, cache: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cache["version"] = GEO_HINT_CACHE_VERSION
    cache["updated_at"] = time.time()
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(cache, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_path, path)


def update_geo_hint_counter(container: dict[str, Any], key: str, code: str, now: float) -> None:
    entry = container.setdefault(key, {"countries": {}, "total": 0})
    if not isinstance(entry, dict):
        container[key] = {"countries": {code: 1}, "total": 1, "updated_at": now}
        return
    countries = entry.setdefault("countries", {})
    if not isinstance(countries, dict):
        countries = {}
        entry["countries"] = countries
    countries[code] = int(countries.get(code) or 0) + 1
    entry["total"] = int(entry.get("total") or 0) + 1
    entry["updated_at"] = now


def geo_hint_cache_update(candidate: Candidate, result: TestResult, args: argparse.Namespace, now: float) -> None:
    code = (result.exit_country_code or "").upper()
    if not code or not getattr(args, "geo_hint_cache_enabled", True):
        return
    cache = getattr(args, "geo_hint_cache", None)
    if not isinstance(cache, dict):
        return

    def update() -> None:
        hosts = cache.setdefault("hosts", {})
        prefixes = cache.setdefault("prefixes", {})
        if isinstance(hosts, dict):
            update_geo_hint_counter(hosts, candidate.host.lower(), code, now)
        prefix = ip_prefix_for_hint(candidate.host)
        if prefix and isinstance(prefixes, dict):
            update_geo_hint_counter(prefixes, prefix, code, now)

    lock = getattr(args, "geo_hint_cache_lock", None)
    if lock is None:
        update()
    else:
        with lock:
            update()


def best_geo_hint_from_entry(entry: Any, min_count: int, min_confidence: float) -> tuple[str, str] | None:
    if not isinstance(entry, dict):
        return None
    countries = entry.get("countries")
    if not isinstance(countries, dict) or not countries:
        return None
    counts = {str(code).upper(): int(count or 0) for code, count in countries.items() if int(count or 0) > 0}
    if not counts:
        return None
    code, count = max(counts.items(), key=lambda item: (item[1], item[0]))
    total = sum(counts.values())
    if count < min_count or total <= 0:
        return None
    confidence = count / total
    if confidence < min_confidence:
        return None
    return code, f"{count}/{total}"


def candidate_geo_hint(candidate: Candidate, args: argparse.Namespace) -> tuple[str, str]:
    if not getattr(args, "geo_hint_cache_enabled", True):
        return "", ""
    cache = getattr(args, "geo_hint_cache", {})
    min_count = max(1, int(getattr(args, "geo_hint_min_count", 1)))
    min_confidence = max(0.0, min(1.0, float(getattr(args, "geo_hint_min_confidence", 0.67))))
    hosts = cache.get("hosts") if isinstance(cache, dict) else None
    if isinstance(hosts, dict):
        result = best_geo_hint_from_entry(hosts.get(candidate.host.lower()), min_count, min_confidence)
        if result:
            code, evidence = result
            return code, f"host:{evidence}"
    prefix = ip_prefix_for_hint(candidate.host)
    prefixes = cache.get("prefixes") if isinstance(cache, dict) else None
    if prefix and isinstance(prefixes, dict):
        result = best_geo_hint_from_entry(prefixes.get(prefix), min_count, min_confidence)
        if result:
            code, evidence = result
            return code, f"prefix:{prefix}:{evidence}"
    return "", ""


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
    if entry.get("policy") != DEFAULT_GEO_POLICY_VERSION:
        return "policy_mismatch", None
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
        "policy": result.geo_policy,
        "selected_provider": result.geo_selected_provider,
        "fallback_used": bool(result.geo_fallback_used),
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
        geo_policy=str(entry.get("policy") or DEFAULT_GEO_POLICY_VERSION),
        geo_selected_provider=str(entry.get("selected_provider") or ""),
        geo_fallback_used=bool(entry.get("fallback_used") or False),
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


def cfst_candidate_source(country: str, port: int) -> str:
    bucket = (country or "unknown").strip().lower()
    return f"cfst_{bucket}_{port}"


def parse_cfst_float(value: Any) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def read_cfst_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            host = str(row.get("IP 地址") or row.get("IP") or "").strip()
            if not host:
                continue
            rows.append(
                {
                    "host": host,
                    "sent": parse_cfst_float(row.get("已发送")),
                    "received": parse_cfst_float(row.get("已接收")),
                    "loss": parse_cfst_float(row.get("丢包率")),
                    "latency_ms": parse_cfst_float(row.get("平均延迟")),
                    "speed_MBps": parse_cfst_float(row.get("下载速度(MB/s)")),
                    "colo": str(row.get("地区码") or "").strip().upper(),
                }
            )
    return rows


def run_cfst_command(cfst_exe: Path, args: list[str], timeout: int) -> None:
    def print_safe(text: str) -> None:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        safe_text = str(text).encode(encoding, errors="replace").decode(encoding, errors="replace")
        print(safe_text, flush=True)

    cmd = [str(cfst_exe), *args]
    print("Running CFST: " + " ".join(cmd), flush=True)
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    output = (proc.stdout or b"").decode(locale.getpreferredencoding(False) or "utf-8", errors="replace").strip()
    if output:
        # Keep CFST progress visible in logs, but avoid flooding normal output
        # with every progress-bar redraw when commands are run by schedulers.
        lines = output.splitlines()
        for line in lines[:80]:
            print_safe(line)
        if len(lines) > 80:
            print_safe(f"... CFST output truncated, total lines={len(lines)}")
    if proc.returncode != 0:
        raise RuntimeError(f"CFST exited {proc.returncode}: {output[-2000:]}")


def cfst_port_args(args: argparse.Namespace) -> list[int]:
    raw = str(getattr(args, "cfst_ports", "") or getattr(args, "cfst_port", 443))
    ports: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        port = int(item)
        if port < 1 or port > 65535:
            raise ValueError(f"invalid CFST port: {port}")
        ports.append(port)
    return ports or [443]


def cfst_country_pool_limit(country: str, args: argparse.Namespace) -> int:
    country = (country or "UNKNOWN").upper()
    overrides = dict(CFST_COUNTRY_POOL_DEFAULTS)
    text = str(getattr(args, "cfst_pool_limits", "") or "")
    for item in text.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        key, value = item.split(":", 1)
        try:
            overrides[key.strip().upper()] = max(0, int(value.strip()))
        except ValueError:
            continue
    if country in overrides:
        return overrides[country]
    return max(0, int(getattr(args, "cfst_other_pool_limit", 70)))


def build_cfst_only_candidates(workdir: Path, args: argparse.Namespace) -> list[Candidate]:
    cfst_exe = Path(args.cfst_exe)
    cfst_ip_file = Path(args.cfst_ip_file)
    if not cfst_exe.exists():
        raise FileNotFoundError(cfst_exe)
    if not cfst_ip_file.exists():
        raise FileNotFoundError(cfst_ip_file)

    ports = cfst_port_args(args)
    if len(ports) != 1:
        raise ValueError("CFST-only first version supports exactly one port")
    port = ports[0]
    started = time.monotonic()
    cfst_dir = workdir / "cfst"
    cfst_dir.mkdir(parents=True, exist_ok=True)
    for stale in workdir.glob("cfst_speed*.csv"):
        try:
            stale.unlink()
        except OSError:
            pass

    latency_path = workdir / f"cfst_latency_{port}.csv"
    httping_input_path = cfst_dir / f"cfst_latency_{port}_ips.txt"
    httping_path = workdir / f"cfst_httping_{port}.csv"

    run_cfst_command(
        cfst_exe,
        [
            "-f",
            str(cfst_ip_file),
            "-tp",
            str(port),
            "-n",
            str(args.cfst_threads),
            "-t",
            str(args.cfst_latency_tests),
            "-tl",
            str(args.cfst_latency_threshold),
            "-tlr",
            str(args.cfst_loss_threshold),
            "-dd",
            "-o",
            str(latency_path),
            "-p",
            "0",
        ],
        timeout=args.cfst_timeout,
    )
    latency_rows = read_cfst_csv(latency_path)
    if not latency_rows:
        raise RuntimeError(f"CFST latency produced no candidates: {latency_path}")
    with httping_input_path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in latency_rows:
            handle.write(str(row["host"]) + "\n")

    httping_rows: list[dict[str, Any]] = []
    httping_attempts = max(1, int(getattr(args, "cfst_httping_retries", 1)))
    for attempt in range(1, httping_attempts + 1):
        run_cfst_command(
            cfst_exe,
            [
                "-f",
                str(httping_input_path),
                "-httping",
                "-tp",
                str(port),
                "-n",
                str(args.cfst_threads),
                "-t",
                str(args.cfst_httping_tests),
                "-tl",
                str(args.cfst_httping_threshold),
                "-tlr",
                str(args.cfst_loss_threshold),
                "-dd",
                "-o",
                str(httping_path),
                "-p",
                "0",
            ],
            timeout=args.cfst_timeout,
        )
        httping_rows = read_cfst_csv(httping_path)
        if httping_rows:
            break
        if attempt < httping_attempts:
            delay = max(0.0, float(getattr(args, "cfst_httping_retry_delay", 3.0)))
            print(
                f"CFST HTTPing produced no rows; retrying {attempt + 1}/{httping_attempts} after {delay:.1f}s",
                flush=True,
            )
            if delay:
                time.sleep(delay)
    httping_by_host = {str(row["host"]): row for row in httping_rows}

    bucket_rows: list[dict[str, Any]] = []
    for row in latency_rows:
        host = str(row["host"])
        http_row = httping_by_host.get(host)
        cfst_colo = str((http_row or {}).get("colo") or "").upper()
        if cfst_colo in {"", "N/A"}:
            cfst_colo = "UNKNOWN"
        declared_country = CFST_COLO_COUNTRY.get(cfst_colo, "")
        bucket = declared_country or "UNKNOWN"
        bucket_rows.append(
            {
                "host": host,
                "port": port,
                "endpoint": format_endpoint(host, port),
                "cfst_colo": cfst_colo,
                "declared_country": declared_country,
                "bucket": bucket,
                "cfst_tcp_latency_ms": row.get("latency_ms"),
                "cfst_httping_latency_ms": (http_row or {}).get("latency_ms"),
                "selected_for_test": False,
                "selection_rank": "",
                "selection_reason": "",
                "source": cfst_candidate_source(bucket, port),
            }
        )

    groups: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for row in bucket_rows:
        groups[str(row["bucket"]).upper()].append(row)

    selected_rows: list[dict[str, Any]] = []
    audit_all = getattr(args, "pool_mode", "direct") == "audit-all"
    for bucket, items in groups.items():
        items.sort(
            key=lambda item: (
                item["cfst_httping_latency_ms"] is None,
                item["cfst_httping_latency_ms"] if item["cfst_httping_latency_ms"] is not None else float("inf"),
                item["cfst_tcp_latency_ms"] if item["cfst_tcp_latency_ms"] is not None else float("inf"),
                item["host"],
            )
        )
        limit = cfst_country_pool_limit(bucket, args)
        keep = items if audit_all or limit <= 0 else items[:limit]
        for rank, item in enumerate(keep, 1):
            item["selected_for_test"] = True
            item["selection_rank"] = rank
            item["selection_reason"] = "audit_all" if audit_all else f"pool_limit={limit or 'all'}"
            selected_rows.append(item)

    selected_rows.sort(
        key=lambda item: (
            {"HK": 0, "SG": 1, "JP": 2, "TW": 3, "KR": 4, "UNKNOWN": 99}.get(str(item["bucket"]).upper(), 20),
            item["cfst_httping_latency_ms"] is None,
            item["cfst_httping_latency_ms"] if item["cfst_httping_latency_ms"] is not None else float("inf"),
            item["cfst_tcp_latency_ms"] if item["cfst_tcp_latency_ms"] is not None else float("inf"),
            item["host"],
        )
    )

    write_cfst_bucket_files(workdir, bucket_rows, selected_rows, args)

    candidates: list[Candidate] = []
    for item in selected_rows:
        bucket = str(item["bucket"]).upper()
        country_label = country_name(bucket if bucket != "UNKNOWN" else None)
        latency = item["cfst_tcp_latency_ms"]
        http_latency = item["cfst_httping_latency_ms"]
        raw = (
            f"{item['endpoint']}#{country_label}|cfst|colo={item['cfst_colo']}"
            f"|tcp={latency if latency is not None else ''}ms"
            f"|httping={http_latency if http_latency is not None else ''}ms"
        )
        candidates.append(
            Candidate(
                source=str(item["source"]),
                raw=raw,
                host=str(item["host"]),
                port=int(item["port"]),
                name=f"cfst|{item['cfst_colo']}",
                declared_latency=float(latency) if latency is not None else None,
                declared_region=bucket if bucket != "UNKNOWN" else None,
                is_cloudflare=is_cloudflare_host(str(item["host"])),
                parse_format="cfst_only",
            )
        )
    args.cfst_bucket_rows = bucket_rows
    args.timings["cfst_discovery"] = time.monotonic() - started
    print(
        f"CFST-only candidates: latency={len(latency_rows)}; "
        f"httping={len(httping_rows)}; selected={len(candidates)}",
        flush=True,
    )
    return candidates


def write_cfst_bucket_files(
    workdir: Path,
    bucket_rows: list[dict[str, Any]],
    selected_rows: list[dict[str, Any]],
    args: argparse.Namespace,
) -> None:
    fields = [
        "host",
        "port",
        "endpoint",
        "cfst_colo",
        "declared_country",
        "bucket",
        "cfst_tcp_latency_ms",
        "cfst_httping_latency_ms",
        "selected_for_test",
        "selection_rank",
        "selection_reason",
        "source",
    ]
    for path, rows in [
        (workdir / "cfst_buckets.csv", bucket_rows),
        (workdir / "cfst_selected_candidates.csv", selected_rows),
    ]:
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

    counts: dict[str, dict[str, Any]] = {}
    selected_keys = {(row["host"], row["port"]) for row in selected_rows}
    for row in bucket_rows:
        bucket = str(row["bucket"]).upper()
        entry = counts.setdefault(
            bucket,
            {"bucket": bucket, "cfst_colos": set(), "total_candidates": 0, "selected_for_test": 0},
        )
        entry["total_candidates"] += 1
        entry["cfst_colos"].add(row["cfst_colo"])
        if (row["host"], row["port"]) in selected_keys:
            entry["selected_for_test"] += 1
    with (workdir / "cfst_buckets_summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["bucket", "cfst_colos", "total_candidates", "selected_for_test", "pool_limit"],
        )
        writer.writeheader()
        for bucket, entry in sorted(counts.items(), key=lambda item: (item[0] == "UNKNOWN", item[0])):
            writer.writerow(
                {
                    "bucket": bucket,
                    "cfst_colos": "|".join(sorted(entry["cfst_colos"])),
                    "total_candidates": entry["total_candidates"],
                    "selected_for_test": entry["selected_for_test"],
                    "pool_limit": cfst_country_pool_limit(bucket, args) or "all",
                }
            )


def write_cfst_post_reports(workdir: Path, results: list[TestResult], args: argparse.Namespace) -> None:
    if getattr(args, "source_mode", "legacy") != "cfst-only":
        return
    bucket_rows = getattr(args, "cfst_bucket_rows", []) or []
    bucket_by_key = {(str(row["host"]), int(row["port"])): row for row in bucket_rows}
    ok_results = [result for result in results if result.ok]
    final_results = select_final_results(ok_results, args)
    final_keys = {result.candidate.key for result in final_results}

    selected_counts: dict[str, dict[str, int]] = collections.defaultdict(lambda: collections.Counter())
    for result in results:
        meta = bucket_by_key.get(result.candidate.key)
        bucket = str((meta or {}).get("bucket") or "UNKNOWN").upper()
        selected_counts[bucket]["tested"] += 1
        if result.ok:
            selected_counts[bucket]["ok"] += 1
        if result.candidate.key in final_keys:
            selected_counts[bucket]["final"] += 1

    summary_path = workdir / "cfst_buckets_summary.csv"
    if summary_path.exists():
        rows: list[dict[str, Any]] = []
        with summary_path.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        with summary_path.open("w", encoding="utf-8-sig", newline="") as handle:
            fields = ["bucket", "cfst_colos", "total_candidates", "selected_for_test", "tested", "ok", "final", "pool_limit"]
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                bucket = str(row["bucket"]).upper()
                counter = selected_counts.get(bucket, {})
                row["tested"] = counter.get("tested", 0)
                row["ok"] = counter.get("ok", 0)
                row["final"] = counter.get("final", 0)
                writer.writerow({field: row.get(field, "") for field in fields})

    consistency: dict[str, dict[str, Any]] = {}
    for result in results:
        meta = bucket_by_key.get(result.candidate.key)
        if not meta:
            continue
        colo = str(meta.get("cfst_colo") or "UNKNOWN").upper()
        declared = str(meta.get("declared_country") or "").upper()
        entry = consistency.setdefault(
            colo,
            {
                "cfst_colo": colo,
                "declared_country": declared,
                "tested_count": 0,
                "true_same_count": 0,
                "true_diff_count": 0,
                "unknown_count": 0,
                "true_country_top": collections.Counter(),
            },
        )
        entry["tested_count"] += 1
        true_country = (result.exit_country_code or "").upper()
        if true_country:
            entry["true_country_top"][true_country] += 1
        if not true_country:
            entry["unknown_count"] += 1
        elif declared and true_country == declared:
            entry["true_same_count"] += 1
        else:
            entry["true_diff_count"] += 1

    with (workdir / "cfst_colo_consistency.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "cfst_colo",
            "declared_country",
            "tested_count",
            "true_same_count",
            "true_diff_count",
            "unknown_count",
            "match_rate",
            "unknown_rate",
            "recommended_trust",
            "true_country_top",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        min_trust = int(getattr(args, "cfst_trust_min_tested", 50))
        for _colo, entry in sorted(consistency.items()):
            tested = max(1, int(entry["tested_count"]))
            match_rate = entry["true_same_count"] / tested
            unknown_rate = entry["unknown_count"] / tested
            recommended = (
                entry["tested_count"] >= min_trust
                and bool(entry["declared_country"])
                and match_rate >= float(getattr(args, "cfst_trust_match_rate", 0.98))
                and unknown_rate <= float(getattr(args, "cfst_trust_unknown_rate", 0.02))
            )
            writer.writerow(
                {
                    "cfst_colo": entry["cfst_colo"],
                    "declared_country": entry["declared_country"],
                    "tested_count": entry["tested_count"],
                    "true_same_count": entry["true_same_count"],
                    "true_diff_count": entry["true_diff_count"],
                    "unknown_count": entry["unknown_count"],
                    "match_rate": f"{match_rate:.6f}",
                    "unknown_rate": f"{unknown_rate:.6f}",
                    "recommended_trust": recommended,
                    "true_country_top": "|".join(
                        f"{country}:{count}" for country, count in entry["true_country_top"].most_common()
                    ),
                }
            )

    run_summary = {
        "source_mode": args.source_mode,
        "pool_mode": getattr(args, "pool_mode", "direct"),
        "cfst_ports": cfst_port_args(args),
        "pool_limits": {
            "HK": cfst_country_pool_limit("HK", args),
            "SG": cfst_country_pool_limit("SG", args),
            "UNKNOWN": cfst_country_pool_limit("UNKNOWN", args),
            "other": args.cfst_other_pool_limit,
        },
        "candidate_count": len([row for row in bucket_rows if row.get("selected_for_test")]),
        "tested_count": len(results),
        "ok_count": len(ok_results),
        "final_count": len(final_results),
        "timings": getattr(args, "timings", {}),
        "speed_tests_enabled": False,
    }

    if getattr(args, "pool_mode", "direct") != "direct":
        pool_rows = update_edgetunnel_node_pool(workdir, results, bucket_by_key, args)
        pool_ok_results = pool_rows_to_results(pool_rows)
        pool_final_results = select_final_results(pool_ok_results, args)
        write_final_from_results(
            workdir / "bestcf_final.txt",
            pool_final_results,
        )
        write_region_counts(workdir / "bestcf_region_counts.csv", pool_ok_results, pool_final_results)
        write_edgetunnel_pool_summary(workdir, pool_rows, pool_final_results)
        pool_status_counts = collections.Counter(str(row.get("status") or "unknown") for row in pool_rows)
        pool_country_counts = collections.Counter(
            str(row.get("true_exit_country") or "UNKNOWN").upper()
            for row in pool_rows
            if row.get("status") == "healthy"
        )
        run_summary.update(
            {
                "pool_file": str(workdir / args.pool_file),
                "pool_total": len(pool_rows),
                "pool_healthy": len(pool_ok_results),
                "pool_final_count": len(pool_final_results),
                "pool_status_counts": dict(sorted(pool_status_counts.items())),
                "pool_healthy_country_counts": dict(sorted(pool_country_counts.items())),
            }
        )
        print(
            f"Pool final generated: healthy={len(pool_ok_results)} final={len(pool_final_results)} "
            f"pool={workdir / args.pool_file}",
            flush=True,
        )

    with (workdir / "cfst_run_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(run_summary, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


POOL_FIELDS = [
    "endpoint",
    "host",
    "port",
    "cfst_colo",
    "declared_country",
    "true_exit_country",
    "true_exit_region_name",
    "exit_ip",
    "cf_colo",
    "geo_evidence",
    "geo_selected_provider",
    "geo_fallback_used",
    "service_score",
    "google_ok",
    "youtube_ok",
    "gpt_ok",
    "proxy_latency_ms",
    "cfst_tcp_latency_ms",
    "cfst_httping_latency_ms",
    "status",
    "fail_reason",
    "first_seen_at",
    "last_seen_at",
    "last_tested_at",
    "success_count",
    "fail_count",
    "consecutive_fail_count",
    "last_success_at",
    "last_failure_at",
    "source",
    "raw_line",
]


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


def int_field(row: dict[str, Any], key: str) -> int:
    try:
        return int(str(row.get(key, "") or "0"))
    except ValueError:
        return 0


def float_field(row: dict[str, Any], key: str) -> float | None:
    return parse_cfst_float(row.get(key))


def bool_field(row: dict[str, Any], key: str) -> bool | None:
    value = str(row.get(key, "")).strip().lower()
    if value in {"true", "1", "yes"}:
        return True
    if value in {"false", "0", "no"}:
        return False
    return None


def load_pool_rows(path: Path) -> dict[tuple[str, int], dict[str, Any]]:
    rows: dict[tuple[str, int], dict[str, Any]] = {}
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            host = str(row.get("host") or "").strip()
            try:
                port = int(str(row.get("port") or "0"))
            except ValueError:
                continue
            if host and port:
                rows[(host.lower(), port)] = row
    return rows


def write_pool_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=POOL_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in POOL_FIELDS})
    os.replace(tmp_path, path)


def result_pool_status(result: TestResult) -> str:
    if result.ok and result.exit_country_code:
        return "healthy"
    if not result.exit_country_code and result.status in {"geo_unknown", "region_unknown", "latency_failed", "latency_too_high"}:
        return "unresolved" if result.status in {"geo_unknown", "region_unknown"} else "failed"
    return "failed"


def update_edgetunnel_node_pool(
    workdir: Path,
    results: list[TestResult],
    bucket_by_key: dict[tuple[str, int], dict[str, Any]],
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    pool_path = workdir / args.pool_file
    existing = load_pool_rows(pool_path)
    timestamp = now_iso()

    for result in results:
        candidate = result.candidate
        key = candidate.key
        meta = bucket_by_key.get(key, {})
        row = dict(existing.get(key, {}))
        first_seen = row.get("first_seen_at") or timestamp
        success_count = int_field(row, "success_count")
        fail_count = int_field(row, "fail_count")
        consecutive_fail = int_field(row, "consecutive_fail_count")
        status = result_pool_status(result)
        if status == "healthy":
            success_count += 1
            consecutive_fail = 0
            last_success_at = timestamp
            last_failure_at = row.get("last_failure_at", "")
        else:
            fail_count += 1
            consecutive_fail += 1
            last_success_at = row.get("last_success_at", "")
            last_failure_at = timestamp
            if consecutive_fail >= int(getattr(args, "pool_cooldown_failures", 5)):
                status = "cooldown"

        row.update(
            {
                "endpoint": candidate.endpoint,
                "host": candidate.host,
                "port": candidate.port,
                "cfst_colo": meta.get("cfst_colo", ""),
                "declared_country": meta.get("declared_country", ""),
                "true_exit_country": result.exit_country_code or "",
                "true_exit_region_name": result.exit_region if result.exit_country_code else "",
                "exit_ip": result.exit_ip or "",
                "cf_colo": result.cf_colo or "",
                "geo_evidence": result.geo_evidence or "",
                "geo_selected_provider": result.geo_selected_provider or "",
                "geo_fallback_used": result.geo_fallback_used,
                "service_score": result.service_score,
                "google_ok": result.google_ok if result.google_ok is not None else "",
                "youtube_ok": result.youtube_ok if result.youtube_ok is not None else "",
                "gpt_ok": result.gpt_ok if result.gpt_ok is not None else "",
                "proxy_latency_ms": f"{result.latency_ms:.0f}" if result.latency_ms is not None else "",
                "cfst_tcp_latency_ms": meta.get("cfst_tcp_latency_ms", candidate.declared_latency or ""),
                "cfst_httping_latency_ms": meta.get("cfst_httping_latency_ms", ""),
                "status": status,
                "fail_reason": "" if status == "healthy" else f"{result.status}: {result.error}",
                "first_seen_at": first_seen,
                "last_seen_at": timestamp,
                "last_tested_at": timestamp,
                "success_count": success_count,
                "fail_count": fail_count,
                "consecutive_fail_count": consecutive_fail,
                "last_success_at": last_success_at,
                "last_failure_at": last_failure_at,
                "source": candidate.source,
                "raw_line": candidate.raw,
            }
        )
        existing[key] = row

    rows = sorted(existing.values(), key=lambda row: (row.get("status") != "healthy", row.get("true_exit_country", ""), row.get("endpoint", "")))
    write_pool_rows(pool_path, rows)
    return rows


def pool_rows_to_results(rows: list[dict[str, Any]]) -> list[TestResult]:
    results: list[TestResult] = []
    for row in rows:
        if row.get("status") != "healthy":
            continue
        country = str(row.get("true_exit_country") or "").upper()
        if not country:
            continue
        host = str(row.get("host") or "")
        try:
            port = int(str(row.get("port") or "0"))
        except ValueError:
            continue
        if not host or not port:
            continue
        candidate = Candidate(
            source=str(row.get("source") or cfst_candidate_source(country, port)),
            raw=str(row.get("raw_line") or f"{format_endpoint(host, port)}#{country_name(country)}|pool"),
            host=host,
            port=port,
            name=f"pool|{row.get('cfst_colo') or ''}",
            declared_latency=float_field(row, "cfst_tcp_latency_ms"),
            declared_region=str(row.get("declared_country") or "") or None,
            is_cloudflare=is_cloudflare_host(host),
            parse_format="pool",
        )
        results.append(
            TestResult(
                candidate,
                True,
                "pool_healthy",
                measured_speed=None,
                latency_ms=float_field(row, "proxy_latency_ms"),
                exit_ip=str(row.get("exit_ip") or "") or None,
                exit_country_code=country,
                exit_region=str(row.get("true_exit_region_name") or country_name(country)),
                cf_colo=str(row.get("cf_colo") or "") or None,
                geo_evidence=str(row.get("geo_evidence") or ""),
                geo_selected_provider=str(row.get("geo_selected_provider") or ""),
                geo_fallback_used=str(row.get("geo_fallback_used")).lower() == "true",
                service_score=int_field(row, "service_score"),
                google_ok=bool_field(row, "google_ok"),
                youtube_ok=bool_field(row, "youtube_ok"),
                gpt_ok=bool_field(row, "gpt_ok"),
                selection_stage="pool",
            )
        )
    return results


def write_final_from_results(path: Path, final_results: list[TestResult]) -> None:
    counters: dict[str, int] = {}
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for result in final_results:
            region = result_region(result)
            counters[region] = counters.get(region, 0) + 1
            line = f"{result.candidate.endpoint}#{region}-{counters[region]}"
            if result.measured_speed is not None:
                line += f"|{result.measured_speed:.2f}MB/s"
            handle.write(line + "\n")


def write_edgetunnel_pool_summary(workdir: Path, rows: list[dict[str, Any]], final_results: list[TestResult]) -> None:
    final_counts = collections.Counter((result.exit_country_code or "").upper() for result in final_results)
    groups: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for row in rows:
        country = str(row.get("true_exit_country") or "UNKNOWN").upper()
        groups[country].append(row)
    with (workdir / "edgetunnel_pool_summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "true_exit_country",
                "total_nodes",
                "healthy_nodes",
                "failed_nodes",
                "unresolved_nodes",
                "cooldown_nodes",
                "selected_count",
                "min_proxy_latency_ms",
                "median_proxy_latency_ms",
            ],
        )
        writer.writeheader()
        for country, items in sorted(groups.items()):
            latencies = [
                value for value in (float_field(row, "proxy_latency_ms") for row in items if row.get("status") == "healthy")
                if value is not None
            ]
            writer.writerow(
                {
                    "true_exit_country": country,
                    "total_nodes": len(items),
                    "healthy_nodes": sum(1 for row in items if row.get("status") == "healthy"),
                    "failed_nodes": sum(1 for row in items if row.get("status") == "failed"),
                    "unresolved_nodes": sum(1 for row in items if row.get("status") == "unresolved"),
                    "cooldown_nodes": sum(1 for row in items if row.get("status") == "cooldown"),
                    "selected_count": final_counts.get(country, 0),
                    "min_proxy_latency_ms": f"{min(latencies):.0f}" if latencies else "",
                    "median_proxy_latency_ms": f"{median_number(latencies):.0f}" if latencies else "",
                }
            )


def curl_text(
    url: str,
    timeout: int = 20,
    proxy: str | None = None,
    headers: dict[str, str] | None = None,
    user_agent: str | None = None,
) -> tuple[bool, str]:
    cmd = [
        "curl.exe",
        "-sS",
        "-L",
        "--compressed",
        "--insecure",
        "--ssl-no-revoke",
        "--max-time",
        str(timeout),
    ]
    if user_agent:
        cmd.extend(["-A", user_agent])
    for key, value in (headers or {}).items():
        cmd.extend(["-H", f"{key}: {value}"])
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
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, UnicodeDecodeError, http.client.IncompleteRead) as exc:
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


def source_quality_score(source: str, source_cache: dict[str, Any]) -> float:
    entries = source_cache.get("sources") if isinstance(source_cache, dict) else None
    if not isinstance(entries, dict):
        return 0.0
    entry = entries.get(source)
    if not isinstance(entry, dict):
        return 0.0
    valid_ratio = float(entry.get("valid_ratio") or 0.0)
    invalid_ratio = float(entry.get("invalid_ratio") or 0.0)
    unique_selected = float(entry.get("unique_selected") or 0.0)
    invalid_streak = float(entry.get("invalid_streak") or 0.0)
    fetch_failed = str(entry.get("last_status") or "") == "source_fetch_failed"
    score = valid_ratio * 100.0
    score += min(unique_selected, 100.0) * 0.4
    score -= invalid_ratio * 80.0
    score -= invalid_streak * 20.0
    if fetch_failed:
        score -= 50.0
    return score


def rank_candidates_by_source_quality(candidates: list[Candidate], source_cache: dict[str, Any]) -> list[Candidate]:
    return sorted(
        candidates,
        key=lambda item: (
            -source_quality_score(item.source, source_cache),
            item.declared_speed is None,
            -(item.declared_speed or 0),
            item.endpoint,
        ),
    )


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


YOUTUBE_GEO_PATTERNS = [
    re.compile(r'"GL"\s*:\s*"([A-Z]{2})"'),
    re.compile(r'"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"'),
    re.compile(r'"countryCode"\s*:\s*"([A-Z]{2})"'),
    re.compile(r'"client"\s*:\s*\{.*?"gl"\s*:\s*"([A-Z]{2})"', re.S),
]


def parse_youtube_geo(text: str) -> str | None:
    for pattern in YOUTUBE_GEO_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1).upper()
    return None


def geo_probe(proxy: str, timeout: int, name: str, url: str) -> tuple[str, str | None, str | None, str | None]:
    headers = None
    user_agent = None
    if name == "youtube":
        headers = {
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
        user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0"
        )
    ok, text = curl_text(url, timeout=timeout, proxy=proxy, headers=headers, user_agent=user_agent)
    if not ok:
        return name, None, None, None
    try:
        if name == "youtube":
            return name, parse_youtube_geo(text), None, None
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


def select_geo_result_by_provider_priority(
    results: list[tuple[str, str | None, str | None, str | None]],
    provider_order: list[str],
) -> tuple[str | None, str, str | None, str | None, str]:
    evidence = ";".join(f"{name}:{code or '-'}" for name, code, _ip, _colo in results)
    selected: tuple[str, str | None, str | None, str | None] | None = None
    for provider in provider_order:
        for name, code, ip, probe_colo in results:
            if name == provider and code:
                selected = (name, code, ip, probe_colo)
                break
        if selected:
            break

    if selected:
        _selected_name, selected_code, exit_ip, colo = selected
        for _name, code, ip, probe_colo in results:
            if code == selected_code:
                exit_ip = exit_ip or ip
                colo = colo or probe_colo
        if exit_ip is None or colo is None:
            for _name, _code, ip, probe_colo in results:
                exit_ip = exit_ip or ip
                colo = colo or probe_colo
        return selected_code, country_name(selected_code), exit_ip, colo, evidence

    exit_ip: str | None = None
    colo: str | None = None
    for _name, _code, ip, probe_colo in results:
        exit_ip = exit_ip or ip
        colo = colo or probe_colo
    return None, "未知", exit_ip, colo, evidence


def geo_decision_from_results(
    results: list[tuple[str, str | None, str | None, str | None]],
    provider_order: list[str],
    policy: str,
    selected_provider: str = "",
    fallback_used: bool = False,
    selection_mode: str = "vote",
) -> GeoDecision:
    if selection_mode == "priority":
        code, region, exit_ip, colo, evidence = select_geo_result_by_provider_priority(results, provider_order)
    else:
        code, region, exit_ip, colo, evidence = select_geo_result(results, provider_order)
    if not selected_provider and code:
        for provider in provider_order:
            for name, result_code, _ip, _colo in results:
                if name == provider and result_code == code:
                    selected_provider = name
                    break
            if selected_provider:
                break
    return GeoDecision(
        country_code=code,
        region=region,
        exit_ip=exit_ip,
        cf_colo=colo,
        evidence=evidence,
        policy=policy,
        selected_provider=selected_provider,
        fallback_used=fallback_used,
    )


def detect_geo(proxy: str, timeout: int, providers: list[str]) -> GeoDecision:
    providers = [provider for provider in providers if provider in GEO_PROVIDER_URLS]
    if not providers:
        providers = list(DEFAULT_GEO_PROVIDERS_DAILY)

    if providers == DEFAULT_GEO_PROVIDERS_DAILY:
        results = run_geo_probes_parallel(proxy, timeout, providers)
        decision = geo_decision_from_results(
            results,
            providers,
            policy=DEFAULT_GEO_POLICY_VERSION,
            selection_mode="priority",
        )
        decision.fallback_used = bool(decision.selected_provider and decision.selected_provider != providers[0])
        return decision

    results = run_geo_probes_parallel(proxy, timeout, providers)
    return geo_decision_from_results(results, providers, policy="provider_vote_v1")


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
        geo = detect_geo(proxy, timeout=args.timeout, providers=args.geo_providers_resolved)
        hint = geo_hint_fields(candidate, args)
        speed, latency, speed_status, error = measure_speed(
            proxy,
            args.speed_urls,
            timeout=args.speed_timeout,
            min_download_bytes=args.min_download_bytes,
        )
        if speed is None:
            result = TestResult(
                candidate,
                False,
                speed_status,
                error or "speed is empty",
                latency_ms=latency,
                **geo_result_fields(geo),
                **hint,
            )
            geo_hint_cache_update(candidate, result, args, time.time())
            return result
        if speed < args.min_speed:
            result = TestResult(
                candidate,
                False,
                "below_min_speed",
                f"{speed:.2f}MB/s < {args.min_speed:.2f}MB/s",
                measured_speed=speed,
                latency_ms=latency,
                **geo_result_fields(geo),
                **hint,
            )
            geo_hint_cache_update(candidate, result, args, time.time())
            return result
        result = TestResult(
            candidate,
            True,
            speed_status,
            measured_speed=speed,
            latency_ms=latency,
            **geo_result_fields(geo),
            **hint,
        )
        geo_hint_cache_update(candidate, result, args, time.time())
        return result
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
    if result.exit_country_code:
        return country_name(result.exit_country_code)
    return result.exit_region or "未知"


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


def country_limit_for_result(result: TestResult, args: argparse.Namespace) -> int:
    code = (result.exit_country_code or "").upper()
    overrides = getattr(args, "country_max_overrides", {}) or {}
    if code and code in overrides:
        return overrides[code]
    return args.country_max


def select_final_results(ok_results: list[TestResult], args: argparse.Namespace) -> list[TestResult]:
    if getattr(args, "selection_mode", "preferred") == "all-regions":
        return select_final_results_all_regions(ok_results, args)

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


def select_final_results_all_regions(ok_results: list[TestResult], args: argparse.Namespace) -> list[TestResult]:
    target_count = args.max_final_candidates
    if not ok_results:
        return []

    groups: dict[str, list[TestResult]] = {}
    for result in ok_results:
        if not result.exit_country_code:
            continue
        groups.setdefault(result_region(result), []).append(result)
    for items in groups.values():
        items.sort(key=result_quality_key)

    selected: list[TestResult] = []
    for _region, items in sorted(
        groups.items(),
        key=lambda item: (
            result_latency(item[1][0]) if item[1] else float("inf"),
            item[0],
        ),
    ):
        region_limit = country_limit_for_result(items[0], args) if items else args.country_max
        keep_items = items[:region_limit] if region_limit > 0 else items
        selected.extend(keep_items)

    if target_count > 0:
        return selected[:target_count]
    return selected


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
                "geo_policy",
                "geo_selected_provider",
                "geo_fallback_used",
                "geo_cache_status",
                "geo_hint_country",
                "geo_hint_source",
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
                    "geo_policy": result.geo_policy,
                    "geo_selected_provider": result.geo_selected_provider,
                    "geo_fallback_used": result.geo_fallback_used,
                    "geo_cache_status": result.geo_cache_status,
                    "geo_hint_country": result.geo_hint_country,
                    "geo_hint_source": result.geo_hint_source,
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

    final_keys = {result.candidate.key for result in final_results}
    if getattr(args, "selection_mode", "preferred") == "all-regions":
        other_region_results = [
            result
            for result in ok_results
            if result.exit_country_code and result.candidate.key not in final_keys
        ]
    else:
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
    write_cfst_post_reports(workdir, results, args)
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
            geo = detect_geo(proxy, timeout=args.timeout, providers=args.geo_providers_resolved)
            hint = geo_hint_fields(candidate, args)
            code = geo.country_code
            if not args.allow_other_regions and code and code.upper() not in args.preferred_countries:
                results.append(
                    TestResult(
                        candidate,
                        False,
                        "region_not_preferred",
                        f"{code} not in {','.join(sorted(args.preferred_countries))}",
                        latency_ms=delay,
                        **geo_result_fields(geo),
                        **hint,
                    )
                )
                geo_hint_cache_update(candidate, results[-1], args, time.time())
                continue
            if not args.allow_unknown_region and not code:
                results.append(
                    TestResult(
                        candidate,
                        False,
                        "region_unknown",
                        "exit country unavailable",
                        latency_ms=delay,
                        **geo_result_fields(geo),
                        **hint,
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
                        **geo_result_fields(geo),
                        **hint,
                    )
                )
                geo_hint_cache_update(candidate, results[-1], args, time.time())
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
                        **geo_result_fields(geo),
                        **hint,
                    )
                )
                geo_hint_cache_update(candidate, results[-1], args, time.time())
                continue
            result = TestResult(
                candidate,
                True,
                speed_status,
                measured_speed=speed,
                latency_ms=delay or speed_latency,
                **geo_result_fields(geo),
                **hint,
            )
            geo_hint_cache_update(candidate, result, args, time.time())
            results.append(result)
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
            hint = geo_hint_fields(candidate, args)
            delay = float(delay_map.get(candidate.key, 0))
            decision, explore = worker_hk_suppression_decision(candidate, args)
            if decision.suppress and not explore:
                results.append(make_geo_quota_skipped_result(candidate, delay, decision, args))
                continue
            switch_error = select_proxy(controller_port, proxy_name, timeout=args.timeout)
            if switch_error:
                results.append(TestResult(candidate, False, "select_proxy_failed", switch_error, latency_ms=delay))
                continue
            cache_status, cache_entry = geo_cache_lookup(candidate, args, time.time())
            if cache_entry:
                cached = test_result_from_geo_cache(candidate, delay, cache_entry, cache_status)
                geo = GeoDecision(
                    country_code=cached.exit_country_code,
                    region=cached.exit_region,
                    exit_ip=cached.exit_ip,
                    cf_colo=cached.cf_colo,
                    evidence=cached.geo_evidence,
                    policy=cached.geo_policy,
                    selected_provider=cached.geo_selected_provider,
                    fallback_used=cached.geo_fallback_used,
                )
                geo_cache_status = cache_status
            else:
                geo = detect_geo(
                    proxy,
                    timeout=args.timeout,
                    providers=args.geo_providers_resolved,
                )
                geo_cache_status = cache_status
            code = geo.country_code
            if not args.allow_other_regions and code and code.upper() not in args.preferred_countries:
                results.append(
                    TestResult(
                        candidate,
                        False,
                        "region_not_preferred",
                        f"{code} not in {','.join(sorted(args.preferred_countries))}",
                        latency_ms=delay,
                        geo_cache_status=geo_cache_status,
                        **geo_result_fields(geo),
                        **hint,
                    )
                )
                if code:
                    update_hk_runtime_suppression_stats(candidate, code, args)
                    geo_hint_cache_update(candidate, results[-1], args, time.time())
                continue
            if not args.allow_unknown_region and not code:
                results.append(
                    TestResult(
                        candidate,
                        False,
                        "region_unknown",
                        "exit country unavailable",
                        latency_ms=delay,
                        geo_cache_status=geo_cache_status,
                        **geo_result_fields(geo),
                        **hint,
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
                    geo_cache_status=geo_cache_status,
                    service_score=service_score,
                    google_ok=google_ok,
                    youtube_ok=youtube_ok,
                    gpt_ok=gpt_ok,
                    service_error=service_error,
                    **geo_result_fields(geo),
                    **hint,
                )
                geo_cache_update(candidate, result, args, time.time())
                update_hk_runtime_suppression_stats(candidate, code, args)
                geo_hint_cache_update(candidate, result, args, time.time())
                results.append(result)
                continue
            result = TestResult(
                candidate,
                True,
                "geo_only" if geo_cache_status != "hit" else "geo_cached",
                latency_ms=delay,
                geo_cache_status=geo_cache_status,
                service_score=service_score,
                google_ok=google_ok,
                youtube_ok=youtube_ok,
                gpt_ok=gpt_ok,
                service_error=service_error,
                **geo_result_fields(geo),
                **hint,
            )
            geo_cache_update(candidate, result, args, time.time())
            update_hk_runtime_suppression_stats(candidate, code, args)
            geo_hint_cache_update(candidate, result, args, time.time())
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


def finish_geo_results_with_speed(
    geo_results: list[TestResult],
    latency_failures: list[TestResult],
    template_proxy: dict[str, Any],
    args: argparse.Namespace,
    geo_tested: int,
    refill_stop_reason: str,
    skipped_latency_pool: list[tuple[str, Candidate, int]],
) -> list[TestResult]:
    all_regions_mode = getattr(args, "selection_mode", "preferred") == "all-regions"
    geo_results, geo_tested = run_target_country_refill(
        geo_results,
        latency_failures,
        template_proxy,
        args,
        geo_tested,
    )
    if all_regions_mode:
        selectable_geo_all = sorted(
            [result for result in geo_results if result.ok and result.exit_country_code],
            key=lambda result: (
                result_region(result),
                result_quality_key(result),
            ),
        )
    else:
        selectable_geo_all = sort_geo_results([result for result in geo_results if result.ok], args.preferred_country_order)
    selectable_geo = selectable_geo_all
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
    if all_regions_mode:
        print(f"All-region geo selected: {len(selectable_geo)} / {len(selectable_geo_all)}", flush=True)
    else:
        print(f"Preferred geo selected: {len(selectable_geo)} / {len(selectable_geo_all)}", flush=True)
    speed_keys = select_speed_sample(selectable_geo, args.speed_bands_parsed, args.speed_limit)
    speed_selected = [result for result in selectable_geo if result.candidate.key in speed_keys]
    geo_only = [result for result in selectable_geo if result.candidate.key not in speed_keys]
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


def final_line_country_code(line: str, candidate: Candidate) -> str:
    label = ""
    if "#" in line:
        label = line.split("#", 1)[1].split("|", 1)[0].strip()
        label = re.sub(r"-\d+$", "", label)
    if re.fullmatch(r"[A-Za-z]{2}", label or ""):
        return label.upper()
    code = country_code_from_text(label) if label else None
    if code:
        return code.upper()
    return str(candidate.declared_region or "").upper()


def validate_final_output(
    path: Path,
    min_lines: int = 10,
    min_regions: int = 1,
    min_country: dict[str, int] | None = None,
) -> tuple[bool, str]:
    if not path.exists() or path.stat().st_size <= 0:
        return False, f"final output is empty or missing: {path}"
    lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    if len(lines) < min_lines:
        return False, f"final output has too few lines: {len(lines)} < {min_lines}"
    invalid: list[str] = []
    regions: set[str] = set()
    country_counts: dict[str, int] = {}
    for line in lines:
        candidate = parse_candidate("validate", line)
        if candidate is None:
            invalid.append(line)
            continue
        code = final_line_country_code(line, candidate)
        if code:
            regions.add(code)
            country_counts[code] = country_counts.get(code, 0) + 1
    if invalid:
        sample = invalid[0][:160]
        return False, f"final output contains invalid endpoint lines: {len(invalid)}; first={sample}"
    if min_regions > 1 and len(regions) < min_regions:
        return False, f"final output has too few declared regions: {len(regions)} < {min_regions}"
    for code, required in (min_country or {}).items():
        actual = country_counts.get(code.upper(), 0)
        if actual < required:
            return False, f"final output has too few {code.upper()} lines: {actual} < {required}"
    country_summary = ",".join(f"{code}:{country_counts[code]}" for code in sorted(country_counts))
    return True, f"final output valid: lines={len(lines)} declared_regions={len(regions)} countries={country_summary}"


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
            "geo_scheduler": "declared-round-robin",
            "geo_country_soft_cap_multiplier": 2.0,
            "geo_country_hard_cap_multiplier": 3.0,
            "geo_cap_countries": "HK,SG",
            "geo_unknown_other_sample_limit": 75,
            "geo_hint_min_count": 1,
            "geo_hint_min_confidence": 0.67,
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
            "geo_scheduler": "declared-round-robin",
            "geo_country_soft_cap_multiplier": 2.0,
            "geo_country_hard_cap_multiplier": 3.0,
            "geo_cap_countries": "HK,SG",
            "geo_unknown_other_sample_limit": 75,
            "geo_hint_min_count": 1,
            "geo_hint_min_confidence": 0.67,
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
            "geo_scheduler": "declared-round-robin",
            "geo_country_soft_cap_multiplier": 2.0,
            "geo_country_hard_cap_multiplier": 3.0,
            "geo_cap_countries": "HK,SG",
            "geo_unknown_other_sample_limit": 100,
            "geo_hint_min_count": 1,
            "geo_hint_min_confidence": 0.67,
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
        "geo_scheduler",
        "geo_country_soft_cap_multiplier",
        "geo_country_hard_cap_multiplier",
        "geo_cap_countries",
        "geo_unknown_other_sample_limit",
        "geo_hint_min_count",
        "geo_hint_min_confidence",
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


def target_country_counts(results: list[TestResult], target_min: dict[str, int]) -> dict[str, int]:
    targets = {code.upper() for code in target_min}
    counts: dict[str, int] = {code: 0 for code in targets}
    for result in results:
        code = (result.exit_country_code or "").upper()
        if result.ok and code in targets:
            counts[code] = counts.get(code, 0) + 1
    return counts


def promote_target_service_fallback(results: list[TestResult], args: argparse.Namespace) -> list[TestResult]:
    target_min = getattr(args, "target_country_min", {}) or {}
    if not target_min:
        return results
    fallback_min = int(getattr(args, "target_refill_min_service_score", 0) or 0)
    if fallback_min <= 0:
        return results

    counts = target_country_counts(results, target_min)
    promoted: list[TestResult] = []
    for result in sorted(results, key=result_quality_key):
        if result.status != "service_check_failed":
            continue
        code = (result.exit_country_code or "").upper()
        if code not in target_min:
            continue
        if counts.get(code, 0) >= target_min[code]:
            continue
        if result.service_score < fallback_min:
            continue
        promoted.append(
            dataclasses.replace(
                result,
                ok=True,
                status="target_service_fallback",
                error=f"{result.error}; accepted by target_refill_min_service_score={fallback_min}",
            )
        )
        counts[code] = counts.get(code, 0) + 1

    if not promoted:
        return results
    promoted_keys = {result.candidate.key for result in promoted}
    kept = [result for result in results if result.candidate.key not in promoted_keys]
    print(
        "Target service fallback promoted: "
        + ",".join(
            f"{code}:{sum(1 for result in promoted if (result.exit_country_code or '').upper() == code)}"
            for code in sorted(target_min)
        ),
        flush=True,
    )
    return kept + promoted


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


def target_refill_candidates_from_latency_failures(
    latency_failures: list[TestResult],
    geo_results: list[TestResult],
    args: argparse.Namespace,
) -> dict[str, list[tuple[str, Candidate, int]]]:
    target_min = getattr(args, "target_country_min", {}) or {}
    thresholds = getattr(args, "target_latency_threshold", {}) or {}
    max_tested = getattr(args, "target_refill_max_tested", {}) or {}
    tested_keys = {result.candidate.key for result in geo_results}
    buckets: dict[str, list[tuple[str, Candidate, int]]] = {code: [] for code in target_min}
    for result in latency_failures:
        if result.status != "latency_too_high":
            continue
        if result.latency_ms is None:
            continue
        if result.candidate.key in tested_keys:
            continue
        delay = int(result.latency_ms)
        for code in target_min:
            threshold = int(thresholds.get(code, 0) or 0)
            if threshold <= 0 or delay > threshold:
                continue
            if not candidate_mentions_country(result.candidate, code):
                continue
            limit = int(max_tested.get(code, 0) or 0)
            if limit > 0 and len(buckets[code]) >= limit:
                continue
            buckets[code].append((f"target-{code.lower()}-{len(buckets[code]) + 1}", result.candidate, delay))
    return buckets


def run_target_country_refill(
    geo_results: list[TestResult],
    latency_failures: list[TestResult],
    template_proxy: dict[str, Any],
    args: argparse.Namespace,
    geo_tested: int,
) -> tuple[list[TestResult], int]:
    target_min = getattr(args, "target_country_min", {}) or {}
    if not target_min:
        return promote_target_service_fallback(geo_results, args), geo_tested

    counts = target_country_counts(geo_results, target_min)
    if all(counts.get(code, 0) >= target for code, target in target_min.items()):
        return promote_target_service_fallback(geo_results, args), geo_tested

    buckets = target_refill_candidates_from_latency_failures(latency_failures, geo_results, args)
    used_keys: set[tuple[str, int]] = set()
    for code in target_min:
        if counts.get(code, 0) >= target_min[code]:
            continue
        batch = [item for item in buckets.get(code, []) if item[1].key not in used_keys]
        if not batch:
            print(f"[target-refill] country={code}; no latency-too-high candidates within target threshold", flush=True)
            continue
        before = counts.get(code, 0)
        print(
            f"[target-refill] country={code}; current={before}/{target_min[code]}; "
            f"testing={len(batch)}; threshold={getattr(args, 'target_latency_threshold', {}).get(code, 0)}ms",
            flush=True,
        )
        batch_results = run_geo_batch(batch, template_proxy, args, f"target_refill_{code.lower()}")
        geo_results.extend(batch_results)
        geo_tested += len(batch)
        used_keys.update(item[1].key for item in batch)
        geo_results = promote_target_service_fallback(geo_results, args)
        counts = target_country_counts(geo_results, target_min)
        print(
            f"[target-refill] country={code}; added={counts.get(code, 0) - before}; "
            f"current={counts.get(code, 0)}/{target_min[code]}",
            flush=True,
        )

    if used_keys:
        latency_failures[:] = [result for result in latency_failures if result.candidate.key not in used_keys]
    geo_results = promote_target_service_fallback(geo_results, args)
    return geo_results, geo_tested


def declared_bucket(candidate: Candidate, preferred_order: list[str], args: argparse.Namespace | None = None) -> str:
    for code in preferred_order:
        if candidate_mentions_country(candidate, code):
            return code
    if args is not None:
        hint_country, _hint_source = candidate_geo_hint(candidate, args)
        promoted_hints = set(GEO_HINT_PROMOTE_COUNTRY_ORDER) & set(preferred_order)
        if hint_country in promoted_hints:
            return f"HINT_{hint_country}"
    if candidate.declared_region:
        return "OTHER"
    return "UNKNOWN"


def declared_bucket_country(bucket_name: str) -> str:
    return bucket_name[5:] if bucket_name.startswith("HINT_") else bucket_name


def declared_geo_bucket_order(preferred_order: list[str]) -> list[str]:
    scarce_order = [code for code in GEO_HINT_PROMOTE_COUNTRY_ORDER if code in preferred_order]
    remaining = [code for code in preferred_order if code not in scarce_order]
    ordered = scarce_order + [f"HINT_{code}" for code in scarce_order]
    ordered.extend(remaining)
    ordered.extend(["UNKNOWN", "OTHER"])
    return ordered


def build_declared_buckets(
    eligible: list[tuple[str, Candidate, int]],
    preferred_order: list[str],
    args: argparse.Namespace | None = None,
) -> dict[str, list[tuple[str, Candidate, int]]]:
    buckets: dict[str, list[tuple[str, Candidate, int]]] = {code: [] for code in declared_geo_bucket_order(preferred_order)}
    buckets["UNKNOWN"] = []
    buckets["OTHER"] = []
    for item in eligible:
        buckets.setdefault(declared_bucket(item[1], preferred_order, args), []).append(item)
    return buckets


def declared_bucket_counts(buckets: dict[str, list[tuple[str, Candidate, int]]]) -> str:
    parts = [f"{name}:{len(items)}" for name, items in buckets.items() if items]
    return " ".join(parts) or "empty"


def pop_declared_geo_batch(
    buckets: dict[str, list[tuple[str, Candidate, int]]],
    order: list[str],
    batch_size: int,
    true_counts: dict[str, int],
    soft_limit: int,
    hard_limit: int,
    suppress_codes: set[str],
) -> list[tuple[str, Candidate, int]]:
    if batch_size <= 0:
        return []
    batch: list[tuple[str, Candidate, int]] = []
    active_order = list(order)
    if not active_order:
        return []
    while len(batch) < batch_size:
        progressed = False
        deferred_soft: list[str] = []
        for bucket_name in active_order:
            if len(batch) >= batch_size:
                break
            items = buckets.get(bucket_name) or []
            if not items:
                continue
            bucket_country = declared_bucket_country(bucket_name)
            if bucket_country in suppress_codes:
                count = true_counts.get(bucket_country, 0)
                if hard_limit > 0 and count >= hard_limit:
                    continue
                if soft_limit > 0 and count >= soft_limit:
                    deferred_soft.append(bucket_name)
                    continue
            batch.append(items.pop(0))
            progressed = True
        if len(batch) >= batch_size:
            break
        for bucket_name in deferred_soft:
            if len(batch) >= batch_size:
                break
            items = buckets.get(bucket_name) or []
            if not items:
                continue
            bucket_country = declared_bucket_country(bucket_name)
            if hard_limit > 0 and true_counts.get(bucket_country, 0) >= hard_limit:
                continue
            batch.append(items.pop(0))
            progressed = True
        if not progressed:
            break
    return batch


def remaining_declared_candidates(buckets: dict[str, list[tuple[str, Candidate, int]]]) -> list[tuple[str, Candidate, int]]:
    remaining: list[tuple[str, Candidate, int]] = []
    for items in buckets.values():
        remaining.extend(items)
    remaining.sort(key=lambda item: (item[2], item[1].endpoint))
    return remaining


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


def hk_suppression_bucket_keys(candidate: Candidate, args: argparse.Namespace) -> list[str]:
    keys: list[str] = []
    scope = str(getattr(args, "hk_suppress_bucket_scope", "source,prefix") or "").lower()
    enabled = {part.strip().replace("-", "_") for part in scope.split(",") if part.strip()}
    if "source" in enabled:
        keys.append(f"source:{candidate.source}")
    if "source_declared" in enabled or "source_decl" in enabled:
        keys.append(f"source_declared:{candidate.source}|{candidate.declared_region or 'UNKNOWN'}")
    if "prefix" in enabled:
        prefix = ip_prefix_for_runtime_suppression(
            candidate.host,
            getattr(args, "hk_suppress_ipv4_prefix", 16),
            getattr(args, "hk_suppress_ipv6_prefix", 32),
        )
        if prefix:
            keys.append(f"prefix:{prefix}")
    return keys


def hk_bucket_is_confident(
    counter: collections.Counter[str],
    min_samples: int,
    confidence: float,
) -> tuple[bool, int, int]:
    counts = {str(code).upper(): int(count) for code, count in counter.items() if int(count) > 0}
    total = sum(counts.values())
    hk = counts.get("HK", 0)
    non_hk = total - hk
    if total <= 0:
        return False, total, hk
    return (
        total >= min_samples
        and hk / total >= confidence
        and non_hk == 0
    ), total, hk


def should_suppress_likely_hk(
    candidate: Candidate,
    bucket_stats: dict[str, collections.Counter[str]],
    hk_count: int,
    args: argparse.Namespace,
) -> HkSuppressionDecision:
    if not getattr(args, "hk_suppression", False):
        return HkSuppressionDecision(False)
    probe_cap = int(getattr(args, "hk_probe_cap", 0) or 0)
    if probe_cap <= 0:
        country_max = int(getattr(args, "country_max", 0) or 0)
        multiplier = float(getattr(args, "hk_probe_cap_multiplier", 3.0) or 0.0)
        probe_cap = int(country_max * multiplier) if country_max > 0 else 0
    if probe_cap <= 0 or hk_count < probe_cap:
        return HkSuppressionDecision(False)

    min_samples = max(1, int(getattr(args, "hk_suppress_min_samples", 20)))
    confidence = max(0.0, min(1.0, float(getattr(args, "hk_suppress_confidence", 0.98))))
    for key in hk_suppression_bucket_keys(candidate, args):
        confident, total, hk = hk_bucket_is_confident(bucket_stats.get(key, collections.Counter()), min_samples, confidence)
        if confident:
            return HkSuppressionDecision(
                True,
                bucket_key=key,
                reason=f"likely HK bucket {key}: {hk}/{total} HK after HK probe cap {probe_cap}",
                total=total,
                hk=hk,
            )
    return HkSuppressionDecision(False)


def stable_exploration_sample(endpoint: str, rate: float) -> bool:
    rate = max(0.0, min(1.0, float(rate)))
    if rate <= 0.0:
        return False
    if rate >= 1.0:
        return True
    digest = hashlib.sha1(endpoint.encode("utf-8", errors="replace")).digest()
    value = int.from_bytes(digest[:8], "big") / float(2**64 - 1)
    return value < rate


def make_geo_quota_skipped_result(
    candidate: Candidate,
    delay: int | float,
    decision: HkSuppressionDecision,
    args: argparse.Namespace,
) -> TestResult:
    return TestResult(
        candidate,
        False,
        "geo_quota_skipped",
        decision.reason or "likely HK bucket suppressed after runtime quota",
        latency_ms=float(delay),
        exit_region="未知",
        geo_cache_status="skipped",
        selection_stage="quota_suppressed",
        **geo_hint_fields(candidate, args),
    )


def update_hk_suppression_stats(
    bucket_stats: dict[str, collections.Counter[str]],
    result: TestResult,
    args: argparse.Namespace,
) -> None:
    code = (result.exit_country_code or "").upper()
    if not code:
        return
    for key in hk_suppression_bucket_keys(result.candidate, args):
        bucket_stats.setdefault(key, collections.Counter())[code] += 1


def update_hk_runtime_suppression_stats(candidate: Candidate, code: str | None, args: argparse.Namespace) -> None:
    code = (code or "").upper()
    if not code or not hk_runtime_suppression_enabled(args):
        return
    lock = getattr(args, "hk_runtime_lock", None)

    def update() -> None:
        stats = getattr(args, "hk_runtime_bucket_stats", None)
        if not isinstance(stats, dict):
            stats = {}
            setattr(args, "hk_runtime_bucket_stats", stats)
        for key in hk_suppression_bucket_keys(candidate, args):
            stats.setdefault(key, collections.Counter())[code] += 1
        if code == "HK":
            setattr(args, "hk_runtime_hk_count", int(getattr(args, "hk_runtime_hk_count", 0) or 0) + 1)

    if lock is None:
        update()
    else:
        with lock:
            update()


def hk_probe_cap(args: argparse.Namespace) -> int:
    cap = int(getattr(args, "hk_probe_cap", 0) or 0)
    if cap > 0:
        return cap
    country_max = int(getattr(args, "country_max", 0) or 0)
    multiplier = float(getattr(args, "hk_probe_cap_multiplier", 3.0) or 0.0)
    return int(country_max * multiplier) if country_max > 0 else 0


def hk_runtime_suppression_enabled(args: argparse.Namespace) -> bool:
    return (
        bool(getattr(args, "hk_suppression", False))
        and getattr(args, "selection_mode", "preferred") == "all-regions"
        and getattr(args, "hk_suppress_strategy", "iterative") == "worker"
    )


def init_hk_runtime_suppression(args: argparse.Namespace) -> None:
    args.hk_runtime_bucket_stats = {}
    args.hk_runtime_lock = threading.Lock()
    args.hk_runtime_hk_count = 0
    args.hk_runtime_quota_skipped = 0
    args.hk_runtime_explored = 0
    args.hk_runtime_suppress_logs = 0


def worker_hk_suppression_decision(candidate: Candidate, args: argparse.Namespace) -> tuple[HkSuppressionDecision, bool]:
    if not hk_runtime_suppression_enabled(args):
        return HkSuppressionDecision(False), False
    lock = getattr(args, "hk_runtime_lock", None)

    def decide() -> tuple[HkSuppressionDecision, bool]:
        stats = getattr(args, "hk_runtime_bucket_stats", {})
        hk_count = int(getattr(args, "hk_runtime_hk_count", 0) or 0)
        decision = should_suppress_likely_hk(candidate, stats, hk_count, args)
        if not decision.suppress:
            return decision, False
        if stable_exploration_sample(candidate.endpoint, args.hk_suppress_explore_rate):
            args.hk_runtime_explored = int(getattr(args, "hk_runtime_explored", 0) or 0) + 1
            return decision, True
        args.hk_runtime_quota_skipped = int(getattr(args, "hk_runtime_quota_skipped", 0) or 0) + 1
        log_limit = int(getattr(args, "hk_suppress_log_limit", 12) or 0)
        log_count = int(getattr(args, "hk_runtime_suppress_logs", 0) or 0)
        if log_count < log_limit:
            print(
                f"[geo-quota] suppress bucket={decision.bucket_key} "
                f"reason={decision.hk}/{decision.total} HK; endpoint={candidate.endpoint}",
                flush=True,
            )
            args.hk_runtime_suppress_logs = log_count + 1
        return decision, False

    if lock is None:
        return decide()
    with lock:
        return decide()


def run_geo_batch(
    items: list[tuple[str, Candidate, int]],
    template_proxy: dict[str, Any],
    args: argparse.Namespace,
    stage: str,
) -> list[TestResult]:
    if not items:
        return []
    stage_started = time.monotonic()
    worker_suppression = hk_runtime_suppression_enabled(args) and stage == "all_regions"
    if worker_suppression:
        init_hk_runtime_suppression(args)
    live_items: list[tuple[str, Candidate, int]] = []
    geo_results: list[TestResult] = []
    for _proxy_name, candidate, delay in items:
        cache_status, cache_entry = geo_cache_lookup(candidate, args, time.time())
        if not cache_entry:
            live_items.append((_proxy_name, candidate, delay))
            continue
        result = test_result_from_geo_cache(candidate, float(delay), cache_entry, cache_status)
        result = dataclasses.replace(result, selection_stage=stage, **geo_hint_fields(candidate, args))
        code = (result.exit_country_code or "").upper()
        if not args.allow_other_regions and code and code not in args.preferred_countries:
            result = dataclasses.replace(
                result,
                ok=False,
                status="region_not_preferred",
                error=f"{code} not in {','.join(sorted(args.preferred_countries))}",
            )
        geo_results.append(result)
        if result.exit_country_code:
            update_hk_runtime_suppression_stats(candidate, result.exit_country_code, args)
    cached_count = len(geo_results)
    if cached_count:
        print(f"[geo-{stage}-cache] hit={cached_count}; live={len(live_items)}", flush=True)
    if not live_items:
        elapsed = time.monotonic() - stage_started
        key = f"geo_{stage}_test"
        args.timings[key] = args.timings.get(key, 0.0) + elapsed
        args.timings["geo_test"] = args.timings.get("geo_test", 0.0) + elapsed
        return geo_results

    geo_chunks = split_evenly(live_items, args.geo_concurrency)
    with ThreadPoolExecutor(max_workers=args.geo_concurrency) as pool:
        futures = [
            pool.submit(test_geo_chunk, chunk, template_proxy, worker_id, args)
            for worker_id, chunk in enumerate(geo_chunks)
            if chunk
        ]
        done = 0
        total = len(live_items)
        for future in as_completed(futures):
            chunk_results = [dataclasses.replace(result, selection_stage=stage) for result in future.result()]
            geo_results.extend(chunk_results)
            done += len(chunk_results)
            ok_count = sum(1 for result in geo_results if result.ok)
            print(f"[geo-{stage} {done}/{total}] cached={cached_count} geo_ok={ok_count}", flush=True)
    elapsed = time.monotonic() - stage_started
    key = f"geo_{stage}_test"
    args.timings[key] = args.timings.get(key, 0.0) + elapsed
    args.timings["geo_test"] = args.timings.get("geo_test", 0.0) + elapsed
    if worker_suppression:
        print(
            f"[geo-quota-worker-summary] hk={int(getattr(args, 'hk_runtime_hk_count', 0) or 0)}; "
            f"skipped={int(getattr(args, 'hk_runtime_quota_skipped', 0) or 0)}; "
            f"explored={int(getattr(args, 'hk_runtime_explored', 0) or 0)}",
            flush=True,
        )
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


def run_declared_round_robin_geo_tests(
    eligible: list[tuple[str, Candidate, int]],
    latency_failures: list[TestResult],
    template_proxy: dict[str, Any],
    args: argparse.Namespace,
) -> list[TestResult]:
    buckets = build_declared_buckets(eligible, args.preferred_country_order, args)
    bucket_order = declared_geo_bucket_order(args.preferred_country_order)
    print(f"Geo declared buckets: {declared_bucket_counts(buckets)}", flush=True)

    geo_results: list[TestResult] = []
    geo_tested = 0
    unknown_other_tested = 0
    refill_stop_reason = ""
    max_geo_tested = args.geo_refill_max_tested
    target_total = args.latency_pool_limit
    soft_limit = int(args.country_max * args.geo_country_soft_cap_multiplier) if args.country_max > 0 else 0
    hard_limit = int(args.country_max * args.geo_country_hard_cap_multiplier) if args.country_max > 0 else 0
    if hard_limit and soft_limit and hard_limit < soft_limit:
        hard_limit = soft_limit

    while any(buckets.values()):
        preferred_geo = sort_geo_results([result for result in geo_results if result.ok], args.preferred_country_order)
        true_counts = preferred_counts(preferred_geo)
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
        batch_size = min(batch_size, args.geo_refill_batch_size)
        if args.geo_unknown_other_sample_limit > 0 and unknown_other_tested >= args.geo_unknown_other_sample_limit:
            active_order = [code for code in bucket_order if code not in {"UNKNOWN", "OTHER"}]
        else:
            active_order = bucket_order
        batch = pop_declared_geo_batch(
            buckets,
            active_order,
            batch_size,
            true_counts,
            soft_limit,
            hard_limit,
            args.geo_cap_countries_resolved,
        )
        if not batch:
            refill_stop_reason = "declared buckets exhausted or capped"
            break
        before = len(preferred_geo)
        before_counts = dict(true_counts)
        unknown_other_tested += sum(
            1
            for _proxy_name, candidate, _delay in batch
            if declared_bucket(candidate, args.preferred_country_order, args) in {"UNKNOWN", "OTHER"}
        )
        batch_results = run_geo_batch(batch, template_proxy, args, "declared")
        geo_tested += len(batch)
        geo_results.extend(batch_results)
        preferred_geo = sort_geo_results([result for result in geo_results if result.ok], args.preferred_country_order)
        true_counts = preferred_counts(preferred_geo)
        count_delta = ";".join(
            f"{code}:{true_counts.get(code, 0) - before_counts.get(code, 0)}"
            for code in args.preferred_country_order
            if true_counts.get(code, 0) - before_counts.get(code, 0)
        ) or "none"
        print(
            f"[geo-declared-summary] tested={geo_tested}; batch={len(batch)}; "
            f"preferred_added={len(preferred_geo) - before}; country_added={count_delta}; "
            f"counts={dict(true_counts)}; remaining={sum(len(items) for items in buckets.values())}; "
            f"unknown_other_tested={unknown_other_tested}/{args.geo_unknown_other_sample_limit or 'inf'}; "
            f"remaining_budget={refill_budget_remaining(args):.1f}s",
            flush=True,
        )
    else:
        refill_stop_reason = "latency candidates exhausted"

    skipped_latency_pool = remaining_declared_candidates(buckets)
    args.timings.setdefault("geo_country_refill_test", 0.0)
    return finish_geo_results_with_speed(
        geo_results,
        latency_failures,
        template_proxy,
        args,
        geo_tested,
        refill_stop_reason,
        skipped_latency_pool,
    )


def run_all_regions_geo_tests_hk_two_phase(
    eligible: list[tuple[str, Candidate, int]],
    latency_failures: list[TestResult],
    template_proxy: dict[str, Any],
    args: argparse.Namespace,
) -> list[TestResult]:
    geo_results: list[TestResult] = []
    bucket_stats: dict[str, collections.Counter[str]] = {}
    geo_tested = 0
    quota_skipped = 0
    explored = 0
    suppress_logs = 0
    refill_stop_reason = "latency candidates exhausted"
    cap = hk_probe_cap(args)
    max_geo_tested = int(getattr(args, "geo_refill_max_tested", 0) or 0)

    requested_probe_size = int(getattr(args, "hk_suppress_probe_batch_size", 0) or 0)
    if requested_probe_size <= 0:
        requested_probe_size = max(cap, int(getattr(args, "geo_refill_batch_size", 75) or 75))
    probe_size = min(len(eligible), max(1, requested_probe_size))
    if max_geo_tested > 0:
        probe_size = min(probe_size, max_geo_tested)

    probe_batch = eligible[:probe_size]
    remaining = list(eligible[probe_size:])
    if probe_batch:
        probe_results = run_geo_batch(probe_batch, template_proxy, args, "all_regions")
        geo_results.extend(probe_results)
        geo_tested += len(probe_batch)
        for result in probe_results:
            update_hk_suppression_stats(bucket_stats, result, args)
    ok_counts = preferred_counts([result for result in geo_results if result.ok])
    print(
        f"[geo-quota-probe] tested={geo_tested}; hk={ok_counts.get('HK', 0)}; "
        f"non_hk={sum(count for code, count in ok_counts.items() if code != 'HK')}; "
        f"remaining={len(remaining)}",
        flush=True,
    )

    test_items: list[tuple[str, Candidate, int]] = []
    skipped_latency_pool: list[tuple[str, Candidate, int]] = []
    hk_count = ok_counts.get("HK", 0)
    for item in remaining:
        _proxy_name, candidate, delay = item
        if max_geo_tested > 0 and geo_tested + len(test_items) >= max_geo_tested:
            skipped_latency_pool.append(item)
            continue
        decision = should_suppress_likely_hk(candidate, bucket_stats, hk_count, args)
        if decision.suppress:
            if stable_exploration_sample(candidate.endpoint, args.hk_suppress_explore_rate):
                explored += 1
                test_items.append(item)
            else:
                quota_skipped += 1
                geo_results.append(make_geo_quota_skipped_result(candidate, delay, decision, args))
                if suppress_logs < int(getattr(args, "hk_suppress_log_limit", 12)):
                    print(
                        f"[geo-quota] suppress bucket={decision.bucket_key} "
                        f"reason={decision.hk}/{decision.total} HK; endpoint={candidate.endpoint}",
                        flush=True,
                    )
                    suppress_logs += 1
            continue
        test_items.append(item)

    if skipped_latency_pool:
        refill_stop_reason = f"geo_refill_max_tested reached {max_geo_tested}/{max_geo_tested}"
        latency_failures.extend(
            TestResult(
                candidate,
                False,
                "latency_pool_skipped",
                refill_stop_reason,
                latency_ms=float(delay),
            )
            for _proxy_name, candidate, delay in skipped_latency_pool
        )

    print(
        f"[geo-quota-plan] probe={len(probe_batch)}; live_remaining={len(test_items)}; "
        f"skipped={quota_skipped}; explored={explored}; latency_skipped={len(skipped_latency_pool)}",
        flush=True,
    )
    if test_items:
        batch_results = run_geo_batch(test_items, template_proxy, args, "all_regions")
        geo_results.extend(batch_results)
        geo_tested += len(test_items)
        for result in batch_results:
            update_hk_suppression_stats(bucket_stats, result, args)
    ok_counts = preferred_counts([result for result in geo_results if result.ok])
    print(
        f"[geo-quota-summary] tested={geo_tested}; hk={ok_counts.get('HK', 0)}; "
        f"non_hk={sum(count for code, count in ok_counts.items() if code != 'HK')}; "
        f"skipped={quota_skipped}; explored={explored}",
        flush=True,
    )
    args.timings.setdefault("geo_country_refill_test", 0.0)
    return finish_geo_results_with_speed(
        geo_results,
        latency_failures,
        template_proxy,
        args,
        geo_tested,
        refill_stop_reason,
        [],
    )


def run_all_regions_geo_tests(
    eligible: list[tuple[str, Candidate, int]],
    latency_failures: list[TestResult],
    template_proxy: dict[str, Any],
    args: argparse.Namespace,
) -> list[TestResult]:
    print(f"Geo all-regions selected: {len(eligible)}", flush=True)
    if not getattr(args, "hk_suppression", False):
        geo_results = run_geo_batch(eligible, template_proxy, args, "all_regions")
        args.timings.setdefault("geo_country_refill_test", 0.0)
        return finish_geo_results_with_speed(
            geo_results,
            latency_failures,
            template_proxy,
            args,
            len(eligible),
            "latency candidates exhausted",
            [],
        )

    print(
        "HK runtime suppression: "
        f"strategy={getattr(args, 'hk_suppress_strategy', 'iterative')} "
        f"enabled cap={hk_probe_cap(args)} min_samples={args.hk_suppress_min_samples} "
        f"confidence={args.hk_suppress_confidence:.3f} explore_rate={args.hk_suppress_explore_rate:.3f} "
        f"bucket_scope={args.hk_suppress_bucket_scope}",
        flush=True,
    )
    if getattr(args, "hk_suppress_strategy", "iterative") == "two-phase":
        return run_all_regions_geo_tests_hk_two_phase(eligible, latency_failures, template_proxy, args)
    if getattr(args, "hk_suppress_strategy", "iterative") == "worker":
        geo_results = run_geo_batch(eligible, template_proxy, args, "all_regions")
        skipped = int(getattr(args, "hk_runtime_quota_skipped", 0) or 0)
        args.timings.setdefault("geo_country_refill_test", 0.0)
        return finish_geo_results_with_speed(
            geo_results,
            latency_failures,
            template_proxy,
            args,
            max(0, len(eligible) - skipped),
            "latency candidates exhausted",
            [],
        )

    remaining: collections.deque[tuple[str, Candidate, int]] = collections.deque(eligible)
    geo_results: list[TestResult] = []
    bucket_stats: dict[str, collections.Counter[str]] = {}
    geo_tested = 0
    quota_skipped = 0
    explored = 0
    suppress_logs = 0
    refill_stop_reason = "latency candidates exhausted"
    last_suppressed_bucket = ""

    while remaining:
        max_geo_tested = int(getattr(args, "geo_refill_max_tested", 0) or 0)
        if max_geo_tested > 0 and geo_tested >= max_geo_tested:
            refill_stop_reason = f"geo_refill_max_tested reached {geo_tested}/{max_geo_tested}"
            latency_failures.extend(
                TestResult(
                    candidate,
                    False,
                    "latency_pool_skipped",
                    refill_stop_reason,
                    latency_ms=float(delay),
                )
                for _proxy_name, candidate, delay in remaining
            )
            remaining.clear()
            break

        batch_size = adaptive_refill_batch_size(args, geo_tested)
        if batch_size < args.geo_refill_min_batch_size:
            refill_stop_reason = (
                f"time budget reserved; batch_size={batch_size}; "
                f"remaining_budget={refill_budget_remaining(args):.1f}s"
            )
            latency_failures.extend(
                TestResult(
                    candidate,
                    False,
                    "latency_pool_skipped",
                    refill_stop_reason,
                    latency_ms=float(delay),
                )
                for _proxy_name, candidate, delay in remaining
            )
            remaining.clear()
            break
        if max_geo_tested > 0:
            batch_size = min(batch_size, max_geo_tested - geo_tested)
        batch_size = min(batch_size, args.geo_refill_batch_size)

        batch: list[tuple[str, Candidate, int]] = []
        while remaining and len(batch) < batch_size:
            item = remaining.popleft()
            _proxy_name, candidate, delay = item
            hk_count = sum(1 for result in geo_results if result.ok and (result.exit_country_code or "").upper() == "HK")
            decision = should_suppress_likely_hk(candidate, bucket_stats, hk_count, args)
            if decision.suppress:
                if stable_exploration_sample(candidate.endpoint, args.hk_suppress_explore_rate):
                    explored += 1
                    batch.append(item)
                else:
                    quota_skipped += 1
                    last_suppressed_bucket = decision.bucket_key
                    geo_results.append(make_geo_quota_skipped_result(candidate, delay, decision, args))
                    if suppress_logs < int(getattr(args, "hk_suppress_log_limit", 12)):
                        print(
                            f"[geo-quota] suppress bucket={decision.bucket_key} "
                            f"reason={decision.hk}/{decision.total} HK; endpoint={candidate.endpoint}",
                            flush=True,
                        )
                        suppress_logs += 1
                continue
            batch.append(item)

        if not batch:
            if remaining:
                continue
            break

        before_ok = len([result for result in geo_results if result.ok and result.exit_country_code])
        batch_results = run_geo_batch(batch, template_proxy, args, "all_regions")
        geo_tested += len(batch)
        geo_results.extend(batch_results)
        for result in batch_results:
            update_hk_suppression_stats(bucket_stats, result, args)
        ok_counts = preferred_counts([result for result in geo_results if result.ok])
        added_ok = len([result for result in geo_results if result.ok and result.exit_country_code]) - before_ok
        print(
            f"[geo-quota-summary] tested={geo_tested}; batch={len(batch)}; "
            f"geo_ok_added={added_ok}; hk={ok_counts.get('HK', 0)}; "
            f"non_hk={sum(count for code, count in ok_counts.items() if code != 'HK')}; "
            f"skipped={quota_skipped}; explored={explored}; remaining={len(remaining)}; "
            f"last_bucket={last_suppressed_bucket or '-'}",
            flush=True,
        )

    args.timings.setdefault("geo_country_refill_test", 0.0)
    return finish_geo_results_with_speed(
        geo_results,
        latency_failures,
        template_proxy,
        args,
        geo_tested,
        refill_stop_reason,
        [],
    )


def run_latency_first_tests(
    candidates: list[Candidate],
    template_proxy: dict[str, Any],
    args: argparse.Namespace,
) -> list[TestResult]:
    stage_started = time.monotonic()
    eligible, latency_failures = run_latency_tests(candidates, template_proxy, args)
    args.timings["latency_test"] = time.monotonic() - stage_started
    print(f"Latency passed: {len(eligible)} / {len(candidates)}", flush=True)

    if args.selection_mode == "all-regions":
        return run_all_regions_geo_tests(eligible, latency_failures, template_proxy, args)

    if args.geo_scheduler == "declared-round-robin":
        return run_declared_round_robin_geo_tests(eligible, latency_failures, template_proxy, args)

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
    skipped_latency_pool = eligible[cursor:]
    return finish_geo_results_with_speed(
        geo_results,
        latency_failures,
        template_proxy,
        args,
        geo_tested,
        refill_stop_reason,
        skipped_latency_pool,
    )


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
    parser.add_argument(
        "--source-mode",
        choices=["legacy", "cfst-only"],
        default="legacy",
        help="candidate source mode; cfst-only fully disables legacy BestCF sources",
    )
    parser.add_argument(
        "--pool-mode",
        choices=["direct", "audit-all", "incremental"],
        default="direct",
        help=(
            "edgetunnel node-pool mode; direct writes final from current run, "
            "audit-all tests every CFST low-latency candidate, incremental updates the pool from the normal CFST subset"
        ),
    )
    parser.add_argument(
        "--pool-file",
        default="edgetunnel_node_pool.csv",
        help="edgetunnel node-pool CSV path relative to workdir unless absolute",
    )
    parser.add_argument(
        "--pool-cooldown-failures",
        type=int,
        default=5,
        help="mark a previously tracked pool node as cooldown after this many consecutive failures",
    )
    parser.add_argument("--cfst-exe", default=str(DEFAULT_CFST_EXE_WINDOWS), help="CloudflareSpeedTest executable path")
    parser.add_argument("--cfst-ip-file", default=str(DEFAULT_CFST_IP_FILE), help="CloudflareSpeedTest IPv4 CIDR file")
    parser.add_argument("--cfst-port", type=int, default=443, help="CFST port for first-version cfst-only mode")
    parser.add_argument("--cfst-ports", default=None, help="reserved comma-separated CFST ports; first version supports one port")
    parser.add_argument("--cfst-threads", type=int, default=300, help="CFST latency/httping worker count")
    parser.add_argument("--cfst-latency-tests", type=int, default=4, help="CFST TCPing test count per IP")
    parser.add_argument("--cfst-httping-tests", type=int, default=2, help="CFST HTTPing test count per IP")
    parser.add_argument("--cfst-latency-threshold", type=int, default=800, help="CFST TCPing max average latency in ms")
    parser.add_argument("--cfst-httping-threshold", type=int, default=1000, help="CFST HTTPing max average latency in ms")
    parser.add_argument("--cfst-loss-threshold", default="0", help="CFST max packet loss ratio")
    parser.add_argument("--cfst-timeout", type=int, default=600, help="CFST command timeout in seconds")
    parser.add_argument("--cfst-httping-retries", type=int, default=2, help="retry CFST HTTPing when it produces no rows")
    parser.add_argument("--cfst-httping-retry-delay", type=float, default=3.0, help="seconds to wait before retrying empty CFST HTTPing")
    parser.add_argument(
        "--cfst-pool-limits",
        default="HK:60,SG:60,UNKNOWN:0",
        help="pre-geo pool limits by declared country; 0 means all, e.g. HK:60,SG:60,UNKNOWN:0",
    )
    parser.add_argument("--cfst-other-pool-limit", type=int, default=70, help="pre-geo pool limit for mapped non-HK/SG countries")
    parser.add_argument("--cfst-trust-min-tested", type=int, default=50, help="minimum tested count before consistency trust recommendation")
    parser.add_argument("--cfst-trust-match-rate", type=float, default=0.98, help="match-rate threshold for trust recommendation")
    parser.add_argument("--cfst-trust-unknown-rate", type=float, default=0.02, help="unknown-rate threshold for trust recommendation")
    parser.add_argument("--no-discover-sources", action="store_true", help="disable bestcf.pages.dev source discovery")
    parser.add_argument("--latency-url", default=DEFAULT_LATENCY_URL, help="URL used by Mihomo delay API")
    parser.add_argument("--latency-timeout", type=int, default=5000, help="Mihomo delay timeout in milliseconds")
    parser.add_argument("--latency-threshold", type=int, default=None, help="max delay in ms before geo pool")
    parser.add_argument("--geo-providers", default=None, help="geo providers: daily, all, or comma-separated names")
    parser.add_argument("--geo-cache", default=None, help="geo cache path")
    parser.add_argument("--geo-cache-ttl-hours", type=float, default=12.0, help="hours before geo cache entries expire")
    parser.add_argument("--no-geo-cache", dest="geo_cache_enabled", action="store_false", help="disable geo cache read/write")
    parser.set_defaults(geo_cache_enabled=True)
    parser.add_argument("--geo-hint-cache", default=None, help="geo hint cache path for declared scheduler")
    parser.add_argument("--no-geo-hint-cache", dest="geo_hint_cache_enabled", action="store_false", help="disable geo hint cache read/write")
    parser.set_defaults(geo_hint_cache_enabled=True)
    parser.add_argument("--geo-hint-min-count", type=int, default=None, help="minimum observations before a geo hint is trusted")
    parser.add_argument("--geo-hint-min-confidence", type=float, default=None, help="minimum top-country ratio before a geo hint is trusted")
    parser.add_argument("--time-budget", type=float, default=None, help="target end-to-end runtime budget in seconds; 0 disables")
    parser.add_argument("--time-safety-margin", type=float, default=None, help="seconds reserved before time budget for speed/write cleanup")
    parser.add_argument("--latency-pool-limit", type=int, default=None, help="target number of preferred geo candidates; 0 disables target")
    parser.add_argument("--max-final-candidates", type=int, default=None, help="maximum preferred candidates written to final output; 0 disables")
    parser.add_argument("--country-max", type=int, default=None, help="maximum final output candidates per exit country; 0 disables")
    parser.add_argument(
        "--country-max-overrides",
        default="",
        help="per-exit-country final cap overrides, e.g. HK:15,JP:50,SG:50",
    )
    parser.add_argument("--final-preferred-latency-ms", type=int, default=None, help="scarce regions prefer nodes no slower than this latency")
    parser.add_argument(
        "--selection-mode",
        choices=["preferred", "all-regions"],
        default="preferred",
        help="final selection mode: preferred country workflow or all detected exit regions",
    )
    parser.add_argument("--geo-initial-limit", type=int, default=None, help="initial latency-ranked candidates selected for geo; 0 means all")
    parser.add_argument("--geo-refill-batch-size", type=int, default=None, help="candidate count per geo refill batch")
    parser.add_argument("--geo-refill-min-batch-size", type=int, default=None, help="stop refill when time budget allows fewer than this batch size")
    parser.add_argument("--geo-refill-max-tested", type=int, default=None, help="maximum geo-tested latency candidates including initial batch; 0 disables")
    parser.add_argument(
        "--geo-scheduler",
        choices=["latency", "declared-round-robin"],
        default=None,
        help="geo test scheduling strategy after latency test",
    )
    parser.add_argument(
        "--geo-country-soft-cap-multiplier",
        type=float,
        default=None,
        help="soft cap for high-volume true exit countries as country_max multiplier",
    )
    parser.add_argument(
        "--geo-country-hard-cap-multiplier",
        type=float,
        default=None,
        help="hard cap for high-volume true exit countries as country_max multiplier",
    )
    parser.add_argument(
        "--geo-cap-countries",
        default=None,
        help="comma-separated true exit country codes controlled by geo soft/hard caps",
    )
    parser.add_argument(
        "--geo-unknown-other-sample-limit",
        type=int,
        default=None,
        help="maximum UNKNOWN/OTHER declared candidates sampled by declared-round-robin scheduler; 0 disables this cap",
    )
    parser.add_argument(
        "--target-country-min",
        default="",
        help="minimum true-exit countries to seek and validate in final output, e.g. JP:10,SG:10",
    )
    parser.add_argument(
        "--target-latency-threshold",
        default="",
        help="per-target-country max delay for quota refill from latency_too_high candidates, e.g. JP:1200,SG:2000",
    )
    parser.add_argument(
        "--target-refill-max-tested",
        default="",
        help="per-target-country maximum latency_too_high candidates tested during target refill, e.g. JP:80,SG:160; 0 disables cap",
    )
    parser.add_argument(
        "--target-refill-min-service-score",
        type=int,
        default=0,
        help="accept target-country service_check_failed nodes with at least this service score when target quota is short; 0 disables",
    )
    parser.add_argument(
        "--hk-suppression",
        dest="hk_suppression",
        action="store_true",
        help="enable runtime suppression for candidates from high-confidence HK buckets in all-regions mode",
    )
    parser.add_argument(
        "--no-hk-suppression",
        dest="hk_suppression",
        action="store_false",
        help="disable runtime HK bucket suppression",
    )
    parser.set_defaults(hk_suppression=False)
    parser.add_argument("--hk-probe-cap", type=int, default=0, help="minimum observed HK geo successes before HK suppression may start; 0 uses country_max * multiplier")
    parser.add_argument("--hk-probe-cap-multiplier", type=float, default=3.0, help="HK suppression probe cap multiplier when --hk-probe-cap is 0")
    parser.add_argument("--hk-suppress-min-samples", type=int, default=10, help="minimum same-bucket observations before a bucket can be suppressed")
    parser.add_argument("--hk-suppress-confidence", type=float, default=0.98, help="minimum HK ratio before a bucket can be suppressed")
    parser.add_argument("--hk-suppress-explore-rate", type=float, default=0.05, help="deterministic exploration rate for suppressed candidates")
    parser.add_argument(
        "--hk-suppress-bucket-scope",
        default="prefix",
        help="comma-separated runtime bucket scopes: prefix,source,source_declared",
    )
    parser.add_argument(
        "--hk-suppress-strategy",
        choices=["worker", "iterative", "two-phase"],
        default="worker",
        help="HK suppression scheduler: in-worker runtime suppression, iterative batches, or one probe batch plus one filtered live batch",
    )
    parser.add_argument(
        "--hk-suppress-probe-batch-size",
        type=int,
        default=300,
        help="probe batch size used by --hk-suppress-strategy two-phase; 0 uses max(hk cap, geo refill batch size)",
    )
    parser.add_argument("--hk-suppress-ipv4-prefix", type=int, default=20, help="IPv4 prefix length used by runtime HK prefix buckets")
    parser.add_argument("--hk-suppress-ipv6-prefix", type=int, default=40, help="IPv6 prefix length used by runtime HK prefix buckets")
    parser.add_argument("--hk-suppress-log-limit", type=int, default=12, help="maximum per-run HK suppression detail log lines")
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
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "validate-output":
        validate_parser = argparse.ArgumentParser(description="Validate generated bestcf_final.txt")
        validate_parser.add_argument("path", help="path to bestcf_final.txt")
        validate_parser.add_argument("--min-lines", type=int, default=10, help="minimum non-empty lines")
        validate_parser.add_argument("--min-regions", type=int, default=1, help="minimum declared regions in final lines")
        validate_parser.add_argument("--min-country", default="", help="minimum final lines by country code, e.g. JP:10,SG:10")
        validate_args = validate_parser.parse_args(argv[1:])
        ok, message = validate_final_output(
            Path(validate_args.path),
            min_lines=max(1, validate_args.min_lines),
            min_regions=max(1, validate_args.min_regions),
            min_country=parse_country_min(validate_args.min_country),
        )
        print(message, flush=True)
        return 0 if ok else 1
    timer = StageTimer()
    args = build_arg_parser().parse_args(argv)
    apply_profile_defaults(args)
    args.concurrency = max(1, args.concurrency)
    args.cfst_threads = max(1, min(1000, int(args.cfst_threads)))
    args.cfst_latency_tests = max(1, int(args.cfst_latency_tests))
    args.cfst_httping_tests = max(1, int(args.cfst_httping_tests))
    args.cfst_latency_threshold = max(1, int(args.cfst_latency_threshold))
    args.cfst_httping_threshold = max(1, int(args.cfst_httping_threshold))
    args.cfst_timeout = max(30, int(args.cfst_timeout))
    args.cfst_httping_retries = max(1, int(args.cfst_httping_retries))
    args.cfst_httping_retry_delay = max(0.0, float(args.cfst_httping_retry_delay))
    args.cfst_other_pool_limit = max(0, int(args.cfst_other_pool_limit))
    args.cfst_trust_min_tested = max(1, int(args.cfst_trust_min_tested))
    args.cfst_trust_match_rate = max(0.0, min(1.0, float(args.cfst_trust_match_rate)))
    args.cfst_trust_unknown_rate = max(0.0, min(1.0, float(args.cfst_trust_unknown_rate)))
    args.pool_cooldown_failures = max(1, int(args.pool_cooldown_failures))
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
    args.geo_country_soft_cap_multiplier = max(0.0, float(args.geo_country_soft_cap_multiplier))
    args.geo_country_hard_cap_multiplier = max(0.0, float(args.geo_country_hard_cap_multiplier))
    args.geo_unknown_other_sample_limit = max(0, int(args.geo_unknown_other_sample_limit))
    args.geo_hint_min_count = max(1, int(args.geo_hint_min_count))
    args.geo_hint_min_confidence = max(0.0, min(1.0, float(args.geo_hint_min_confidence)))
    args.hk_probe_cap = max(0, int(args.hk_probe_cap))
    args.hk_probe_cap_multiplier = max(0.0, float(args.hk_probe_cap_multiplier))
    args.hk_suppress_min_samples = max(1, int(args.hk_suppress_min_samples))
    args.hk_suppress_confidence = max(0.0, min(1.0, float(args.hk_suppress_confidence)))
    args.hk_suppress_explore_rate = max(0.0, min(1.0, float(args.hk_suppress_explore_rate)))
    args.hk_suppress_probe_batch_size = max(0, int(args.hk_suppress_probe_batch_size))
    args.hk_suppress_ipv4_prefix = max(0, min(32, int(args.hk_suppress_ipv4_prefix)))
    args.hk_suppress_ipv6_prefix = max(0, min(128, int(args.hk_suppress_ipv6_prefix)))
    args.hk_suppress_log_limit = max(0, int(args.hk_suppress_log_limit))
    args.geo_cap_countries_resolved = {
        item.strip().upper()
        for item in str(args.geo_cap_countries or "").split(",")
        if item.strip()
    }
    args.preferred_country_min = parse_country_min(args.preferred_country_min)
    args.country_max_overrides = parse_country_min(args.country_max_overrides)
    args.target_country_min = parse_country_min(args.target_country_min)
    args.target_latency_threshold = parse_country_min(args.target_latency_threshold)
    args.target_refill_max_tested = parse_country_min(args.target_refill_max_tested)
    args.target_refill_min_service_score = max(0, min(3, int(args.target_refill_min_service_score)))
    args.timings = timer.timings
    args.run_started_at = timer.started_at
    args.preferred_country_order = [
        item.strip().upper()
        for item in str(args.preferred_countries).split(",")
        if item.strip()
    ] or list(PREFERRED_COUNTRY_ORDER)
    args.preferred_countries = set(args.preferred_country_order)
    if args.selection_mode == "all-regions":
        args.allow_other_regions = True
        args.preferred_country_min = {}
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    args.geo_cache_path = Path(args.geo_cache) if args.geo_cache else workdir / DEFAULT_GEO_CACHE_NAME
    args.geo_cache = load_geo_cache(args.geo_cache_path) if args.geo_cache_enabled else {"version": GEO_CACHE_VERSION, "entries": {}}
    args.geo_cache_lock = threading.Lock()
    args.geo_hint_cache_path = Path(args.geo_hint_cache) if args.geo_hint_cache else workdir / DEFAULT_GEO_HINT_CACHE_NAME
    args.geo_hint_cache = load_geo_hint_cache(args.geo_hint_cache_path) if args.geo_hint_cache_enabled else empty_geo_hint_cache()
    args.geo_hint_cache_lock = threading.Lock()
    if not args.keep_workers:
        clean_workers(workdir)
    timer.mark("setup")

    source_failures: list[dict[str, str]] = []
    parse_failures: list[dict[str, str]] = []
    if args.source_mode == "cfst-only":
        print("Building CFST-only candidates...", flush=True)
        candidates = build_cfst_only_candidates(workdir, args)
        rows = [(candidate.source, candidate.raw) for candidate in candidates]
        write_raw(workdir, rows)
        write_parsed(workdir, candidates)
        total_unique = len(candidates)
        # Keep compatibility with existing copy/report steps.
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
                ],
            )
            writer.writeheader()
            by_source = collections.Counter(candidate.source for candidate in candidates)
            for source, count in sorted(by_source.items()):
                writer.writerow(
                    {
                        "source": source,
                        "url": str(Path(args.cfst_ip_file)),
                        "status": "cfst_only",
                        "raw_lines": count,
                        "nonempty_lines": count,
                        "valid_lines": count,
                        "invalid_lines": 0,
                        "valid_ratio": "1.000000",
                        "invalid_ratio": "0.000000",
                        "unique_selected": count,
                    }
                )
        print(f"CFST-only selected for test: {len(candidates)}", flush=True)
    else:
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
        candidates = rank_candidates_by_source_quality(candidates, source_cache)
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
    if args.limit > 0:
        candidates = candidates[: args.limit]

    print(f"Fetched lines: {len(rows)}", flush=True)
    print(f"Parsed unique candidates: {total_unique}; selected for test: {len(candidates)}", flush=True)
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
        output_path = Path(args.output)
        if final.resolve() != output_path.resolve():
            shutil.copyfile(final, output_path)
        final = output_path
    if args.geo_cache_enabled:
        save_geo_cache(args.geo_cache_path, args.geo_cache)
    if args.geo_hint_cache_enabled:
        save_geo_hint_cache(args.geo_hint_cache_path, args.geo_hint_cache)
    args.timings["write_results"] = time.monotonic() - stage_started
    print(f"Final output: {final}", flush=True)
    print(f"Successful: {sum(1 for result in results if result.ok)}; failed: {sum(1 for result in results if not result.ok)}", flush=True)
    print(timer.summary(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
