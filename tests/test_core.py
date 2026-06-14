import tempfile
import unittest
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


class ValidateOutputTests(unittest.TestCase):
    def test_validate_rejects_invalid_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bestcf_final.txt"
            path.write_text("not-an-endpoint\n", encoding="utf-8")
            ok, _message = tool.validate_final_output(path, min_lines=1)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
