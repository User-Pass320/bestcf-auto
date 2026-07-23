import argparse
import datetime as dt
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any


TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
TUNNEL_PATTERN = re.compile(
    r"(?:^|[^a-z])(tun|tap|wintun|wireguard|tailscale|zerotier|vpn|clash|mihomo|v2ray|sing-box)(?:[^a-z]|$)",
    re.IGNORECASE,
)


def parse_trace(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def fetch_direct_trace(url: str, timeout: int) -> dict[str, str]:
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    request = urllib.request.Request(url, headers={"User-Agent": "bestcf-direct-preflight/1"})
    with opener.open(request, timeout=timeout) as response:
        content = response.read().decode("utf-8", errors="replace")
    return parse_trace(content)


def windows_network_state() -> dict[str, Any]:
    command = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$routeRows = foreach ($route in (Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop)) {
  $ipif = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1
  $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
  [pscustomobject]@{
    interface_index = [int]$route.InterfaceIndex
    route_metric = [int]$route.RouteMetric
    interface_metric = if ($ipif) { [int]$ipif.InterfaceMetric } else { 999999 }
    total_metric = [int]$route.RouteMetric + $(if ($ipif) { [int]$ipif.InterfaceMetric } else { 999999 })
    next_hop = [string]$route.NextHop
    interface_alias = [string]$route.InterfaceAlias
    adapter_name = if ($adapter) { [string]$adapter.Name } else { '' }
    adapter_description = if ($adapter) { [string]$adapter.InterfaceDescription } else { '' }
    adapter_status = if ($adapter) { [string]$adapter.Status } else { '' }
    hardware_interface = if ($adapter) { [bool]$adapter.HardwareInterface } else { $false }
  }
}
$activeAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up' | ForEach-Object {
  [pscustomobject]@{
    interface_index = [int]$_.ifIndex
    name = [string]$_.Name
    description = [string]$_.InterfaceDescription
    hardware_interface = [bool]$_.HardwareInterface
  }
})
$selected = $routeRows | Sort-Object total_metric,route_metric,interface_metric | Select-Object -First 1
[pscustomobject]@{ default_route=$selected; active_adapters=$activeAdapters } | ConvertTo-Json -Depth 5 -Compress
"""
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        timeout=20,
        check=False,
    )
    stdout = (proc.stdout or b"").decode("utf-8", errors="replace").lstrip("\ufeff")
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError((stderr or stdout or "route inspection failed").strip())
    data = json.loads(stdout)
    if not isinstance(data, dict) or not data.get("default_route"):
        raise RuntimeError("no IPv4 default route found")
    return data


def tunnel_adapters(state: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for adapter in state.get("active_adapters") or []:
        text = f"{adapter.get('name', '')} {adapter.get('description', '')}"
        if TUNNEL_PATTERN.search(text):
            found.append(adapter)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail closed unless candidate tests will leave through a CN physical route.")
    parser.add_argument("--expected-interface-index", type=int, default=0)
    parser.add_argument("--expected-loc", default="CN")
    parser.add_argument("--trace-url", default=TRACE_URL)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    failures: list[str] = []
    state: dict[str, Any] = {}
    if os.name != "nt":
        failures.append("physical-route inspection is implemented for Windows only")
    else:
        try:
            state = windows_network_state()
        except Exception as exc:
            failures.append(f"route inspection failed: {exc}")

    route = state.get("default_route") or {}
    route_index = int(route.get("interface_index") or 0)
    if args.expected_interface_index > 0 and route_index != args.expected_interface_index:
        failures.append(
            f"default route interface index {route_index} != expected {args.expected_interface_index}"
        )
    route_text = f"{route.get('interface_alias', '')} {route.get('adapter_name', '')} {route.get('adapter_description', '')}"
    if route_text.strip() and TUNNEL_PATTERN.search(route_text):
        failures.append(f"default route is a tunnel/proxy adapter: {route_text.strip()}")
    active_tunnels = tunnel_adapters(state)
    if active_tunnels:
        failures.append(
            "active tunnel/proxy adapters detected: "
            + ", ".join(str(item.get("name") or item.get("description")) for item in active_tunnels)
        )

    trace: dict[str, str] = {}
    try:
        trace = fetch_direct_trace(args.trace_url, max(1, args.timeout))
    except Exception as exc:
        failures.append(f"direct Cloudflare trace failed: {exc}")
    expected_loc = args.expected_loc.strip().upper()
    actual_loc = str(trace.get("loc") or "").upper()
    if actual_loc != expected_loc:
        failures.append(f"direct trace loc={actual_loc or 'UNKNOWN'} != {expected_loc}")

    report = {
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "ok": not failures,
        "expected_loc": expected_loc,
        "trace": trace,
        "expected_interface_index": max(0, args.expected_interface_index),
        "network": state,
        "active_tunnel_adapters": active_tunnels,
        "proxy_environment_present": {
            name: bool(os.environ.get(name))
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
        },
        "failures": failures,
    }
    output = Path(args.output_json)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), flush=True)
    if failures:
        print("CN direct preflight failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
