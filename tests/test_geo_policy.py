import unittest

import geo_policy


class StrictGeoPolicyTests(unittest.TestCase):
    def test_vietnam_is_normalized_to_hong_kong(self):
        self.assertEqual("HK", geo_policy.normalize_country("vn"))
        decision = geo_policy.decide_strict("VN", "HK", ping0_ip="203.0.113.1")
        self.assertEqual("confirmed_hk", decision.status)
        self.assertEqual("HK", decision.country)

    def test_strict_decision_matrix(self):
        cases = [
            ("SG", "SG", "confirmed_non_hk", "SG"),
            ("HK", "HK", "confirmed_hk", "HK"),
            ("HK", "SG", "hk_suspect", None),
            ("SG", "HK", "hk_suspect", None),
            ("SG", "JP", "geo_mismatch", None),
            (None, "SG", "geo_unknown", None),
            ("SG", None, "geo_unknown", None),
        ]
        for youtube, ping0, status, country in cases:
            with self.subTest(youtube=youtube, ping0=ping0):
                decision = geo_policy.decide_strict(youtube, ping0)
                self.assertEqual(status, decision.status)
                self.assertEqual(country, decision.country)

    def test_evidence_preserves_raw_country_and_attempt(self):
        observations = [
            geo_policy.ProbeObservation("youtube", None, raw_country=None, status="unknown"),
            geo_policy.ProbeObservation("youtube", "VN", raw_country="VN", attempt=2),
            geo_policy.ProbeObservation("ping0", "HK", raw_country="HK"),
        ]
        decision = geo_policy.decide_from_observations(observations)
        self.assertEqual("confirmed_hk", decision.status)
        self.assertEqual("youtube:-;youtube_retry1:VN;ping0:HK", decision.evidence)
        parsed = geo_policy.parse_evidence(decision.evidence)
        retry = next(row for row in parsed if row.provider == "youtube" and row.attempt == 2)
        self.assertEqual("VN", retry.raw_country)
        self.assertEqual("HK", retry.country)


if __name__ == "__main__":
    unittest.main()
