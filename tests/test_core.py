import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

import bestcf_tool as tool


class ParseCandidateTests(unittest.TestCase):
    def test_parse_ipv4_endpoint_with_comment(self):
        candidate = tool.parse_candidate("src", "1.2.3.4:8443#US | sample")
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.host, "1.2.3.4")
        self.assertEqual(candidate.port, 8443)
        self.assertEqual(candidate.declared_region, "US")

    def test_parse_ipv6_endpoint(self):
        candidate = tool.parse_candidate("src", "[2606:4700::1]:443#SG")
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.host, "2606:4700::1")
        self.assertEqual(candidate.port, 443)

    def test_parse_region_prefers_specific_chinese_regions(self):
        self.assertEqual(tool.parse_region("2a09:bac1::1 中国 香港 香港 — Cloudflare"), "HK")
        self.assertEqual(tool.parse_region("2a09:bac1::1 中国 台湾 台湾 — Cloudflare"), "TW")
        self.assertEqual(tool.parse_region("2a09:bac1::1 中国 澳门 澳门 — Cloudflare"), "MO")
        self.assertEqual(tool.parse_region("203.0.113.1 中国 广东 广州"), "CN")


class GeoPolicyTests(unittest.TestCase):
    def test_daily_policy_short_circuits_on_ping0_success(self):
        calls = []

        def fake_probe(_proxy, _timeout, name, _url):
            calls.append(name)
            return name, "HK", "203.0.113.1", None

        with mock.patch.object(tool, "geo_probe", side_effect=fake_probe):
            decision = tool.detect_geo("http://127.0.0.1:7890", 1, tool.DEFAULT_GEO_PROVIDERS_DAILY)

        self.assertEqual(calls, ["ping0"])
        self.assertEqual(decision.country_code, "HK")
        self.assertEqual(decision.selected_provider, "ping0")
        self.assertFalse(decision.fallback_used)

    def test_daily_policy_falls_back_to_ipwhois(self):
        calls = []

        def fake_probe(_proxy, _timeout, name, _url):
            calls.append(name)
            if name == "ping0":
                return name, None, None, None
            return name, "JP", "203.0.113.2", None

        with mock.patch.object(tool, "geo_probe", side_effect=fake_probe):
            decision = tool.detect_geo("http://127.0.0.1:7890", 1, tool.DEFAULT_GEO_PROVIDERS_DAILY)

        self.assertEqual(calls, ["ping0", "ipwhois"])
        self.assertEqual(decision.country_code, "JP")
        self.assertEqual(decision.selected_provider, "ipwhois")
        self.assertTrue(decision.fallback_used)


class SourceQualityTests(unittest.TestCase):
    def test_source_quality_ranking_prioritizes_cached_productive_source(self):
        fast_low_quality = tool.Candidate(
            source="low",
            raw="1.1.1.1:443",
            host="1.1.1.1",
            port=443,
            declared_speed=99.0,
        )
        productive = tool.Candidate(
            source="high",
            raw="2.2.2.2:443",
            host="2.2.2.2",
            port=443,
            declared_speed=1.0,
        )
        cache = {
            "sources": {
                "high": {"valid_ratio": 1.0, "invalid_ratio": 0.0, "unique_selected": 80},
                "low": {"valid_ratio": 0.1, "invalid_ratio": 0.9, "unique_selected": 1},
            }
        }

        ranked = tool.rank_candidates_by_source_quality([fast_low_quality, productive], cache)
        self.assertEqual(ranked[0].source, "high")


class DeclaredSchedulerTests(unittest.TestCase):
    def test_declared_bucket_prefers_country_mentions(self):
        candidate = tool.Candidate(source="src", raw="1.1.1.1:443#美国 US", host="1.1.1.1", port=443)
        self.assertEqual(tool.declared_bucket(candidate, ["JP", "SG", "US", "HK"]), "US")

    def test_declared_bucket_uses_geo_hint_when_declaration_unknown(self):
        candidate = tool.Candidate(source="src", raw="1.2.3.4:443", host="1.2.3.4", port=443)
        args = Namespace(
            geo_hint_cache_enabled=True,
            geo_hint_cache={"hosts": {"1.2.3.4": {"countries": {"JP": 2}, "total": 2}}, "prefixes": {}},
            geo_hint_min_count=1,
            geo_hint_min_confidence=0.67,
        )

        self.assertEqual(tool.declared_bucket(candidate, ["JP", "SG", "US", "HK"], args), "HINT_JP")

    def test_declared_bucket_does_not_promote_common_geo_hint(self):
        candidate = tool.Candidate(source="src", raw="1.2.3.4:443", host="1.2.3.4", port=443)
        args = Namespace(
            geo_hint_cache_enabled=True,
            geo_hint_cache={"hosts": {"1.2.3.4": {"countries": {"HK": 2}, "total": 2}}, "prefixes": {}},
            geo_hint_min_count=1,
            geo_hint_min_confidence=0.67,
        )

        self.assertEqual(tool.declared_bucket(candidate, ["JP", "SG", "US", "HK"], args), "UNKNOWN")
        self.assertNotIn("HINT_HK", tool.declared_geo_bucket_order(["JP", "SG", "US", "HK"]))

    def test_declared_bucket_keeps_declaration_before_geo_hint(self):
        candidate = tool.Candidate(source="src", raw="1.2.3.4:443#SG", host="1.2.3.4", port=443)
        args = Namespace(
            geo_hint_cache_enabled=True,
            geo_hint_cache={"hosts": {"1.2.3.4": {"countries": {"JP": 2}, "total": 2}}, "prefixes": {}},
            geo_hint_min_count=1,
            geo_hint_min_confidence=0.67,
        )

        self.assertEqual(tool.declared_bucket(candidate, ["JP", "SG", "US", "HK"], args), "SG")

    def test_ip_prefix_for_hint_uses_ipv4_24(self):
        self.assertEqual(tool.ip_prefix_for_hint("1.2.3.4"), "1.2.3.0/24")

    def test_candidate_geo_hint_uses_prefix_when_host_missing(self):
        candidate = tool.Candidate(source="src", raw="1.2.3.4:443", host="1.2.3.4", port=443)
        args = Namespace(
            geo_hint_cache_enabled=True,
            geo_hint_cache={"hosts": {}, "prefixes": {"1.2.3.0/24": {"countries": {"KR": 3}, "total": 3}}},
            geo_hint_min_count=2,
            geo_hint_min_confidence=0.67,
        )

        country, source = tool.candidate_geo_hint(candidate, args)

        self.assertEqual(country, "KR")
        self.assertTrue(source.startswith("prefix:1.2.3.0/24:"))

    def test_pop_declared_geo_batch_defers_soft_capped_bucket(self):
        hk = tool.Candidate(source="src", raw="1.1.1.1:443#HK", host="1.1.1.1", port=443)
        jp = tool.Candidate(source="src", raw="2.2.2.2:443#JP", host="2.2.2.2", port=443)
        buckets = {
            "HK": [("p1", hk, 10)],
            "JP": [("p2", jp, 20)],
            "UNKNOWN": [],
            "OTHER": [],
        }

        batch = tool.pop_declared_geo_batch(
            buckets,
            ["HK", "JP", "UNKNOWN", "OTHER"],
            batch_size=1,
            true_counts={"HK": 100},
            soft_limit=100,
            hard_limit=150,
            suppress_codes={"HK"},
        )

        self.assertEqual(batch[0][1].host, "2.2.2.2")
        self.assertEqual(len(buckets["HK"]), 1)

    def test_pop_declared_geo_batch_respects_active_order(self):
        unknown = tool.Candidate(source="src", raw="1.1.1.1:443", host="1.1.1.1", port=443)
        jp = tool.Candidate(source="src", raw="2.2.2.2:443#JP", host="2.2.2.2", port=443)
        buckets = {
            "JP": [("p2", jp, 20)],
            "UNKNOWN": [("p1", unknown, 10)],
            "OTHER": [],
        }

        batch = tool.pop_declared_geo_batch(
            buckets,
            ["JP"],
            batch_size=2,
            true_counts={},
            soft_limit=0,
            hard_limit=0,
            suppress_codes=set(),
        )

        self.assertEqual([item[1].host for item in batch], ["2.2.2.2"])
        self.assertEqual(len(buckets["UNKNOWN"]), 1)

    def test_run_geo_batch_reuses_geo_cache_without_live_worker(self):
        candidate = tool.Candidate(source="src", raw="1.2.3.4:443", host="1.2.3.4", port=443)
        args = Namespace(
            geo_cache_enabled=True,
            geo_cache={
                "entries": {
                    candidate.endpoint: {
                        "endpoint": candidate.endpoint,
                        "exit_ip": "203.0.113.1",
                        "exit_country_code": "JP",
                        "exit_region": "日本",
                        "cf_colo": "NRT",
                        "geo_evidence": "cached",
                        "policy": tool.DEFAULT_GEO_POLICY_VERSION,
                        "selected_provider": "ping0",
                        "fallback_used": False,
                        "providers": list(tool.DEFAULT_GEO_PROVIDERS_DAILY),
                        "expires_at": 9999999999,
                    }
                }
            },
            geo_providers_resolved=list(tool.DEFAULT_GEO_PROVIDERS_DAILY),
            geo_hint_cache_enabled=False,
            allow_other_regions=True,
            preferred_countries={"JP", "SG", "US", "HK"},
            geo_concurrency=1,
            timings={},
        )

        with mock.patch.object(tool, "test_geo_chunk", side_effect=AssertionError("live worker called")):
            results = tool.run_geo_batch([("p1", candidate, 123)], {}, args, "declared")

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].ok)
        self.assertEqual(results[0].status, "geo_cached")
        self.assertEqual(results[0].exit_country_code, "JP")
        self.assertEqual(results[0].selection_stage, "declared")


class AllRegionsSelectionTests(unittest.TestCase):
    def make_result(self, endpoint: str, code: str, latency: int) -> tool.TestResult:
        host, port = endpoint.rsplit(":", 1)
        candidate = tool.Candidate(source="src", raw=endpoint, host=host, port=int(port))
        return tool.TestResult(
            candidate,
            True,
            "geo_only",
            latency_ms=latency,
            exit_country_code=code,
            exit_region=tool.country_name(code),
            geo_evidence=f"ping0:{code}",
            geo_selected_provider="ping0",
        )

    def test_all_regions_selection_caps_each_detected_region(self):
        results = [
            self.make_result("1.1.1.1:443", "HK", 30),
            self.make_result("1.1.1.2:443", "HK", 10),
            self.make_result("1.1.1.3:443", "HK", 20),
            self.make_result("2.2.2.1:443", "JP", 50),
            self.make_result("2.2.2.2:443", "JP", 40),
            self.make_result("3.3.3.3:443", "", 1),
        ]
        args = Namespace(selection_mode="all-regions", country_max=2, max_final_candidates=0)

        selected = tool.select_final_results(results, args)

        self.assertEqual([result.candidate.endpoint for result in selected], [
            "1.1.1.2:443",
            "1.1.1.3:443",
            "2.2.2.2:443",
            "2.2.2.1:443",
        ])
        self.assertEqual(sum(1 for result in selected if result.exit_country_code == "HK"), 2)
        self.assertEqual(sum(1 for result in selected if result.exit_country_code == "JP"), 2)

    def test_all_regions_mode_tests_every_latency_passed_candidate(self):
        candidates = [
            tool.Candidate(source="src", raw=f"1.1.1.{index}:443", host=f"1.1.1.{index}", port=443)
            for index in range(1, 4)
        ]
        eligible = [(f"p{index}", candidate, index * 10) for index, candidate in enumerate(candidates, start=1)]
        args = Namespace(
            selection_mode="all-regions",
            preferred_country_order=["HK"],
            speed_bands_parsed=[],
            speed_limit=0,
            speed_concurrency=1,
            time_budget=0,
            run_started_at=0,
            speed_timeout=1,
            start_timeout=0,
            timings={},
        )

        def fake_geo_batch(items, _template_proxy, _args, stage):
            return [
                tool.TestResult(
                    candidate,
                    True,
                    "geo_only",
                    latency_ms=delay,
                    exit_country_code="HK",
                    exit_region="香港",
                    selection_stage=stage,
                )
                for _proxy_name, candidate, delay in items
            ]

        with mock.patch.object(tool, "run_geo_batch", side_effect=fake_geo_batch) as geo_mock:
            results = tool.run_all_regions_geo_tests(eligible, [], {}, args)

        geo_mock.assert_called_once()
        self.assertEqual(len(geo_mock.call_args.args[0]), len(eligible))
        self.assertEqual(len([result for result in results if result.ok]), len(eligible))
        self.assertEqual([result.selection_stage for result in results], ["all_regions"] * len(eligible))


class ValidateOutputTests(unittest.TestCase):
    def test_validate_rejects_invalid_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bestcf_final.txt"
            path.write_text("not-an-endpoint\n", encoding="utf-8")
            ok, _message = tool.validate_final_output(path, min_lines=1)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
