import base64
import importlib.util
import json
import os
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

import bestcf_tool as tool


def load_script(name: str, filename: str):
    path = Path(__file__).resolve().parents[1] / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify_final = load_script("verify_final_true_exit", "verify-final-true-exit.py")
merge_lines = load_script("merge_line_results", "merge-line-results.py")


class ExternalSourceTests(unittest.TestCase):
    def test_s5gy_is_a_first_class_allowed_source(self):
        self.assertEqual(tool.DEFAULT_SOURCES["s5gy"], "https://bestcf.pages.dev/s5gy/all.txt")
        self.assertEqual(
            tool.normalize_source_url("https://bestcf.pages.dev/s5gy/all.txt"),
            "https://bestcf.pages.dev/s5gy/all.txt",
        )

    def test_extracts_common_subscription_endpoints(self):
        vmess = base64.urlsafe_b64encode(
            json.dumps({"add": "104.16.1.1", "port": "443"}).encode()
        ).decode().rstrip("=")
        lines = "\n".join(
            [
                "vless://uuid@104.17.1.2:8443?security=tls#vless",
                f"vmess://{vmess}",
                "trojan://password@[2606:4700::1]:2053#trojan",
            ]
        )
        subscription = base64.b64encode(lines.encode()).decode()
        self.assertCountEqual(
            tool.extract_subscription_endpoints(subscription),
            [("104.17.1.2", 8443), ("104.16.1.1", 443), ("2606:4700::1", 2053)],
        )

    def test_extracts_unique_endpoints_from_clash_yaml(self):
        content = """
proxies:
  - {name: one, type: vless, server: edge.example.com, port: 443}
  - {name: duplicate, type: vmess, server: edge.example.com, port: 443}
  - {name: ipv6, type: trojan, server: '2001:db8::1', port: 8443}
  - {name: invalid, type: ss, server: '', port: 0}
"""
        self.assertEqual(
            [("edge.example.com", 443), ("2001:db8::1", 8443)],
            tool.extract_clash_yaml_endpoints(content),
        )


class CloudflareExpansionTests(unittest.TestCase):
    def test_expands_only_confirmed_cloudflare_hosts(self):
        cf = tool.Candidate("cf", "104.16.1.1:443", "104.16.1.1", 443, is_cloudflare=True)
        other = tool.Candidate("vps", "1.1.1.1:443", "1.1.1.1", 443, is_cloudflare=False)
        expanded = tool.expand_cloudflare_candidates([cf, other], list(tool.CF_TLS_PORTS))
        cf_ports = {item.port for item in expanded if item.host == "104.16.1.1"}
        other_ports = {item.port for item in expanded if item.host == "1.1.1.1"}
        self.assertEqual(cf_ports, set(tool.CF_TLS_PORTS))
        self.assertEqual(other_ports, {443})

    def test_rejects_non_tls_cloudflare_port(self):
        with self.assertRaises(ValueError):
            tool.parse_cloudflare_tls_ports("443,80")


class RollingPoolTests(unittest.TestCase):
    def make_args(self, pool_file: str) -> Namespace:
        return Namespace(
            pool_file=pool_file,
            pool_cooldown_failures=3,
            pool_success_ttl_days=14.0,
            latency_observations={},
            line_id="ct",
        )

    def test_last_good_metadata_survives_until_third_consecutive_failure(self):
        candidate = tool.Candidate("src", "104.16.1.1:443", "104.16.1.1", 443, is_cloudflare=True)
        success = tool.TestResult(
            candidate,
            True,
            "geo_only",
            latency_ms=100,
            exit_ip="203.0.113.10",
            exit_country_code="JP",
            exit_region="日本",
        )
        failure = tool.TestResult(candidate, False, "latency_failed", "timeout")
        with tempfile.TemporaryDirectory() as temp:
            args = self.make_args("pool.csv")
            rows = tool.update_edgetunnel_node_pool(Path(temp), [success], {}, args)
            self.assertEqual(rows[0]["status"], "healthy")
            rows = tool.update_edgetunnel_node_pool(Path(temp), [failure], {}, args)
            self.assertEqual(rows[0]["status"], "probation")
            self.assertEqual(rows[0]["true_exit_country"], "JP")
            rows = tool.update_edgetunnel_node_pool(Path(temp), [failure], {}, args)
            self.assertEqual(rows[0]["status"], "probation")
            rows = tool.update_edgetunnel_node_pool(Path(temp), [failure], {}, args)
            self.assertEqual(rows[0]["status"], "cooldown")

    def test_expired_success_is_not_eligible(self):
        row = {
            "status": "healthy",
            "host": "104.16.1.1",
            "port": "443",
            "true_exit_country": "JP",
            "true_exit_region_name": "日本",
            "last_success_at": "2000-01-01T00:00:00+00:00",
        }
        self.assertEqual(tool.pool_rows_to_results([row], ttl_days=14), [])


class DiversitySelectionTests(unittest.TestCase):
    def result(self, host: str, port: int, country: str, exit_ip: str) -> tool.TestResult:
        candidate = tool.Candidate("src", f"{host}:{port}", host, port)
        return tool.TestResult(
            candidate,
            True,
            "geo_only",
            exit_country_code=country,
            exit_region=tool.country_name(country),
            exit_ip=exit_ip,
        )

    def test_final_verifier_caps_host_ports_and_exit_ip(self):
        results = [
            self.result("104.16.1.1", 443, "HK", "203.0.113.1"),
            self.result("104.16.1.1", 2053, "HK", "203.0.113.2"),
            self.result("104.16.1.1", 8443, "HK", "203.0.113.3"),
            self.result("104.16.1.2", 443, "HK", "203.0.113.1"),
            self.result("104.16.1.3", 443, "HK", "203.0.113.1"),
        ]
        selected = verify_final.select_verified_results(
            results,
            country_max=30,
            country_max_overrides={"HK": 20},
            max_final_candidates=0,
            host_max_ports=2,
            exit_ip_max=2,
        )
        self.assertEqual(sum(item.candidate.host == "104.16.1.1" for item in selected), 2)
        self.assertLessEqual(sum(item.exit_ip == "203.0.113.1" for item in selected), 2)

    def test_multiline_union_prioritizes_broader_coverage(self):
        a = tool.Candidate("a", "104.16.1.1:443", "104.16.1.1", 443)
        b = tool.Candidate("b", "104.16.1.2:443", "104.16.1.2", 443)
        rows = merge_lines.merge_observations(
            [
                {"line_id": "ct", "candidate": a, "country": "JP"},
                {"line_id": "cu", "candidate": a, "country": "JP"},
                {"line_id": "ct", "candidate": b, "country": "SG"},
            ],
            {},
        )
        self.assertEqual(rows[0]["candidate"].key, a.key)
        self.assertEqual(rows[0]["passed_line_count"], 2)


class DirectEnvironmentTests(unittest.TestCase):
    def test_direct_subprocess_environment_drops_proxy_variables(self):
        with mock.patch.dict(
            os.environ,
            {"HTTP_PROXY": "http://127.0.0.1:7897", "https_proxy": "http://127.0.0.1:7897"},
            clear=False,
        ):
            env = tool.direct_subprocess_env()
        self.assertNotIn("HTTP_PROXY", env)
        self.assertNotIn("https_proxy", env)
        self.assertEqual(env["NO_PROXY"], "*")


if __name__ == "__main__":
    unittest.main()
