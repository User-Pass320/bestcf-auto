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
    def test_daily_policy_prefers_ping0_over_crosscheck_disagreement(self):
        calls = []

        def fake_probe(_proxy, _timeout, name, _url):
            calls.append(name)
            if name == "ping0":
                return name, "HK", "203.0.113.1", None
            return name, "SG", "203.0.113.2", None

        with mock.patch.object(tool, "geo_probe", side_effect=fake_probe):
            decision = tool.detect_geo("http://127.0.0.1:7890", 1, tool.DEFAULT_GEO_PROVIDERS_DAILY)

        self.assertCountEqual(calls, ["ping0", "ipwhois", "ip_api"])
        self.assertEqual(decision.country_code, "HK")
        self.assertEqual(decision.selected_provider, "ping0")
        self.assertFalse(decision.fallback_used)
        self.assertEqual(tool.parse_geo_evidence(decision.evidence), {"ping0": "HK", "ipwhois": "SG", "ip_api": "SG"})

    def test_daily_policy_falls_back_to_ipwhois_when_ping0_unknown(self):
        calls = []

        def fake_probe(_proxy, _timeout, name, _url):
            calls.append(name)
            if name == "ping0":
                return name, None, None, None
            if name == "ipwhois":
                return name, "JP", "203.0.113.2", None
            return name, "SG", "203.0.113.3", None

        with mock.patch.object(tool, "geo_probe", side_effect=fake_probe):
            decision = tool.detect_geo("http://127.0.0.1:7890", 1, tool.DEFAULT_GEO_PROVIDERS_DAILY)

        self.assertCountEqual(calls, ["ping0", "ipwhois", "ip_api"])
        self.assertEqual(decision.country_code, "JP")
        self.assertEqual(decision.selected_provider, "ipwhois")
        self.assertTrue(decision.fallback_used)

    def test_daily_policy_falls_back_to_ip_api_when_ping0_and_ipwhois_unknown(self):
        calls = []

        def fake_probe(_proxy, _timeout, name, _url):
            calls.append(name)
            if name in {"ping0", "ipwhois"}:
                return name, None, None, None
            return name, "TW", "203.0.113.3", None

        with mock.patch.object(tool, "geo_probe", side_effect=fake_probe):
            decision = tool.detect_geo("http://127.0.0.1:7890", 1, tool.DEFAULT_GEO_PROVIDERS_DAILY)

        self.assertCountEqual(calls, ["ping0", "ipwhois", "ip_api"])
        self.assertEqual(decision.country_code, "TW")
        self.assertEqual(decision.selected_provider, "ip_api")
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


class HkSuppressionTests(unittest.TestCase):
    def make_candidate(self, endpoint: str = "104.17.1.1:443", source: str = "src") -> tool.Candidate:
        host, port = endpoint.rsplit(":", 1)
        return tool.Candidate(source=source, raw=endpoint, host=host, port=int(port))

    def make_args(self, **overrides):
        values = {
            "hk_suppression": True,
            "hk_probe_cap": 105,
            "hk_probe_cap_multiplier": 3.0,
            "country_max": 35,
            "hk_suppress_min_samples": 20,
            "hk_suppress_confidence": 0.98,
            "hk_suppress_bucket_scope": "prefix",
            "hk_suppress_strategy": "worker",
            "hk_suppress_probe_batch_size": 300,
            "hk_suppress_ipv4_prefix": 20,
            "hk_suppress_ipv6_prefix": 40,
            "hk_suppress_explore_rate": 0.05,
            "geo_hint_cache_enabled": False,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_hk_suppression_waits_until_probe_cap(self):
        candidate = self.make_candidate()
        stats = {"prefix:104.17.0.0/20": tool.collections.Counter({"HK": 20})}

        decision = tool.should_suppress_likely_hk(candidate, stats, 104, self.make_args())

        self.assertFalse(decision.suppress)

    def test_hk_suppression_suppresses_confident_prefix_bucket(self):
        candidate = self.make_candidate()
        stats = {"prefix:104.17.0.0/20": tool.collections.Counter({"HK": 20})}

        decision = tool.should_suppress_likely_hk(candidate, stats, 105, self.make_args())

        self.assertTrue(decision.suppress)
        self.assertEqual(decision.bucket_key, "prefix:104.17.0.0/20")

    def test_hk_suppression_requires_min_samples(self):
        candidate = self.make_candidate()
        stats = {"prefix:104.17.0.0/20": tool.collections.Counter({"HK": 19})}

        decision = tool.should_suppress_likely_hk(candidate, stats, 105, self.make_args())

        self.assertFalse(decision.suppress)

    def test_hk_suppression_does_not_suppress_mixed_bucket(self):
        candidate = self.make_candidate()
        stats = {"prefix:104.17.0.0/20": tool.collections.Counter({"HK": 20, "JP": 1})}

        decision = tool.should_suppress_likely_hk(candidate, stats, 105, self.make_args())

        self.assertFalse(decision.suppress)

    def test_hk_suppression_can_use_source_bucket(self):
        candidate = self.make_candidate(source="pure_hk")
        stats = {"source:pure_hk": tool.collections.Counter({"HK": 20})}

        decision = tool.should_suppress_likely_hk(
            candidate,
            stats,
            105,
            self.make_args(hk_suppress_bucket_scope="source"),
        )

        self.assertTrue(decision.suppress)
        self.assertEqual(decision.bucket_key, "source:pure_hk")

    def test_stable_exploration_sample_boundaries_and_stability(self):
        endpoint = "104.17.1.1:443"

        self.assertFalse(tool.stable_exploration_sample(endpoint, 0.0))
        self.assertTrue(tool.stable_exploration_sample(endpoint, 1.0))
        self.assertEqual(
            tool.stable_exploration_sample(endpoint, 0.05),
            tool.stable_exploration_sample(endpoint, 0.05),
        )

    def test_all_regions_hk_suppression_skips_only_confident_bucket(self):
        candidates = [
            self.make_candidate(f"104.17.0.{index}:443", "hk_src")
            for index in range(1, 24)
        ]
        jp_candidate = self.make_candidate("203.0.113.1:443", "jp_src")
        eligible = [(f"p{index}", candidate, 10 + index) for index, candidate in enumerate(candidates, start=1)]
        eligible.append(("pjp", jp_candidate, 999))
        args = Namespace(
            selection_mode="all-regions",
            hk_suppression=True,
            hk_probe_cap=5,
            hk_probe_cap_multiplier=3.0,
            country_max=35,
            hk_suppress_min_samples=5,
            hk_suppress_confidence=0.98,
            hk_suppress_bucket_scope="prefix",
            hk_suppress_strategy="iterative",
            hk_suppress_probe_batch_size=300,
            hk_suppress_ipv4_prefix=20,
            hk_suppress_ipv6_prefix=40,
            hk_suppress_explore_rate=0.0,
            hk_suppress_log_limit=0,
            geo_refill_batch_size=6,
            geo_refill_min_batch_size=1,
            geo_refill_max_tested=0,
            time_budget=0,
            time_safety_margin=0,
            run_started_at=0,
            timings={},
            speed_bands_parsed=[],
            speed_limit=0,
            speed_concurrency=1,
            speed_timeout=1,
            start_timeout=0,
            geo_hint_cache_enabled=False,
        )

        def fake_geo_batch(items, _template_proxy, _args, stage):
            results = []
            for _proxy_name, candidate, delay in items:
                code = "JP" if candidate is jp_candidate else "HK"
                results.append(
                    tool.TestResult(
                        candidate,
                        True,
                        "geo_only",
                        latency_ms=delay,
                        exit_country_code=code,
                        exit_region=tool.country_name(code),
                        selection_stage=stage,
                    )
                )
            return results

        with mock.patch.object(tool, "run_geo_batch", side_effect=fake_geo_batch):
            results = tool.run_all_regions_geo_tests(eligible, [], {}, args)

        skipped = [result for result in results if result.status == "geo_quota_skipped"]
        ok = [result for result in results if result.ok]

        self.assertGreaterEqual(len(skipped), 1)
        self.assertTrue(all(result.candidate.source == "hk_src" for result in skipped))
        self.assertEqual(sum(1 for result in ok if result.exit_country_code == "JP"), 1)

    def test_worker_hk_suppression_skips_inside_geo_batch(self):
        candidates = [
            self.make_candidate(f"104.17.0.{index}:443", "hk_src")
            for index in range(1, 10)
        ]
        eligible = [(f"p{index}", candidate, 10 + index) for index, candidate in enumerate(candidates, start=1)]
        args = Namespace(
            selection_mode="all-regions",
            hk_suppression=True,
            hk_probe_cap=3,
            hk_probe_cap_multiplier=3.0,
            country_max=35,
            hk_suppress_min_samples=3,
            hk_suppress_confidence=0.98,
            hk_suppress_bucket_scope="prefix",
            hk_suppress_strategy="worker",
            hk_suppress_probe_batch_size=300,
            hk_suppress_ipv4_prefix=20,
            hk_suppress_ipv6_prefix=40,
            hk_suppress_explore_rate=0.0,
            hk_suppress_log_limit=0,
            geo_concurrency=1,
            geo_cache_enabled=False,
            geo_cache={"entries": {}},
            allow_other_regions=True,
            preferred_countries={"HK"},
            allow_unknown_region=False,
            service_check=False,
            min_service_score=0,
            timeout=1,
            timings={},
            geo_hint_cache_enabled=False,
        )

        def fake_geo_chunk(chunk, _template_proxy, _worker_id, chunk_args):
            results = []
            tool.init_hk_runtime_suppression(chunk_args)
            for _proxy_name, candidate, delay in chunk:
                decision, explore = tool.worker_hk_suppression_decision(candidate, chunk_args)
                if decision.suppress and not explore:
                    results.append(tool.make_geo_quota_skipped_result(candidate, delay, decision, chunk_args))
                    continue
                result = tool.TestResult(
                    candidate,
                    True,
                    "geo_only",
                    latency_ms=delay,
                    exit_country_code="HK",
                    exit_region="香港",
                )
                tool.update_hk_runtime_suppression_stats(candidate, "HK", chunk_args)
                results.append(result)
            return results

        with mock.patch.object(tool, "test_geo_chunk", side_effect=fake_geo_chunk):
            results = tool.run_geo_batch(eligible, {}, args, "all_regions")

        self.assertEqual(sum(1 for result in results if result.ok), 3)
        self.assertEqual(sum(1 for result in results if result.status == "geo_quota_skipped"), 6)


class ValidateOutputTests(unittest.TestCase):
    def test_validate_rejects_invalid_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bestcf_final.txt"
            path.write_text("not-an-endpoint\n", encoding="utf-8")
            ok, _message = tool.validate_final_output(path, min_lines=1)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
