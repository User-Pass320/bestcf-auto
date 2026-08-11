import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bestcf_tool as tool


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "verify-final-true-exit.py"
SPEC = importlib.util.spec_from_file_location("verify_final_true_exit", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


class StrictYoutubePing0DecisionTests(unittest.TestCase):
    @staticmethod
    def make_result(evidence: str, selected_country: str = "SG") -> tool.TestResult:
        candidate = tool.Candidate(source="test", raw="1.1.1.1:443", host="1.1.1.1", port=443)
        return tool.TestResult(
            candidate,
            True,
            "geo_only",
            exit_ip="203.0.113.1",
            exit_country_code=selected_country,
            exit_region=tool.country_name(selected_country),
            geo_evidence=evidence,
        )

    def test_accepts_matching_providers(self):
        decision = verify.strict_youtube_ping0_decision(self.make_result("youtube:SG;ping0:SG"), {})
        self.assertEqual(decision.country_code, "SG")
        self.assertEqual(decision.reason, "accepted")

    def test_rejects_provider_mismatch(self):
        decision = verify.strict_youtube_ping0_decision(self.make_result("youtube:SG;ping0:HK"), {})
        self.assertEqual(decision.country_code, "UNKNOWN")
        self.assertEqual(decision.reason, "provider_mismatch")

    def test_accepts_provider_mismatch_using_ping0(self):
        decision = verify.strict_youtube_ping0_decision(
            self.make_result("youtube:SG;ping0:HK"),
            {},
            mismatch_policy="ping0",
        )
        self.assertEqual(decision.country_code, "HK")
        self.assertEqual(decision.reason, "accepted_ping0_override")

    def test_ping0_override_applies_country_alias(self):
        decision = verify.strict_youtube_ping0_decision(
            self.make_result("youtube:JP;ping0:VN"),
            {"VN": "HK"},
            mismatch_policy="ping0",
        )
        self.assertEqual(decision.country_code, "HK")
        self.assertEqual(decision.ping0_country, "HK")

    def test_rejects_when_either_provider_is_unknown(self):
        decision = verify.strict_youtube_ping0_decision(self.make_result("youtube:-;ping0:SG"), {})
        self.assertEqual(decision.country_code, "UNKNOWN")
        self.assertEqual(decision.reason, "provider_unknown")

    def test_applies_vn_to_hk_alias_before_comparison(self):
        decision = verify.strict_youtube_ping0_decision(
            self.make_result("youtube:VN;ping0:HK", selected_country="VN"),
            {"VN": "HK"},
        )
        self.assertEqual(decision.country_code, "HK")
        self.assertEqual(decision.reason, "accepted")


class FinalVerificationFlowTests(unittest.TestCase):
    def run_flow(self, rows, min_lines=3, min_regions=3, mismatch_policy="reject"):
        tempdir = tempfile.TemporaryDirectory()
        root = Path(tempdir.name)
        input_path = root / "candidate.txt"
        output_path = root / "verified.txt"
        summary_path = root / "summary.json"
        details_path = root / "details.csv"
        input_path.write_text(
            "\n".join(f"{endpoint}#{label}" for endpoint, label, _youtube, _ping0 in rows) + "\n",
            encoding="utf-8",
        )
        parsed_rows = verify.read_final_rows(input_path)
        results = []
        for parsed, (_endpoint, _label, youtube, ping0) in zip(parsed_rows, rows):
            selected = youtube or ping0
            results.append(
                tool.TestResult(
                    parsed["candidate"],
                    bool(selected),
                    "geo_only" if selected else "geo_unknown",
                    exit_ip="203.0.113.1" if ping0 else None,
                    exit_country_code=selected,
                    exit_region=tool.country_name(selected),
                    geo_evidence=f"youtube:{youtube or '-'};ping0:{ping0 or '-'}",
                )
            )
        argv = [
            str(SCRIPT_PATH),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--workdir",
            str(root / "work"),
            "--template",
            str(root / "template.yaml"),
            "--mihomo",
            str(root / "mihomo.exe"),
            "--providers",
            "youtube,ping0",
            "--provider-mismatch-policy",
            mismatch_policy,
            "--actual-country-aliases",
            "VN:HK",
            "--min-lines",
            str(min_lines),
            "--min-regions",
            str(min_regions),
            "--details-csv",
            str(details_path),
            "--summary-json",
            str(summary_path),
        ]
        with mock.patch.object(verify.tool, "load_template", return_value={}), mock.patch.object(
            verify.tool, "run_geo_batch", return_value=results
        ), mock.patch.object(sys, "argv", argv):
            outcome = None
            try:
                outcome = verify.main()
            except SystemExit as exc:
                outcome = exc
        return tempdir, output_path, summary_path, details_path, outcome

    def test_unknown_candidates_are_dropped_without_failing_valid_batch(self):
        tempdir, output_path, summary_path, _details_path, outcome = self.run_flow(
            [
                ("1.1.1.1:443", "SG", "SG", "SG"),
                ("2.2.2.2:443", "JP", "JP", "JP"),
                ("3.3.3.3:443", "US", "US", "US"),
                ("4.4.4.4:443", "HK", "", "HK"),
            ]
        )
        self.addCleanup(tempdir.cleanup)
        self.assertEqual(outcome, 0)
        self.assertEqual(len(output_path.read_text(encoding="utf-8").splitlines()), 3)
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(summary["input_count"], 4)
        self.assertEqual(summary["verified_count"], 3)
        self.assertEqual(summary["dropped_unknown_count"], 1)
        self.assertEqual(summary["dropped_mismatch_count"], 0)
        self.assertEqual(summary["strict_rejected_count"], 1)
        self.assertEqual(summary["dropped_by_verification_reason"], {"provider_unknown": 1})
        self.assertTrue(summary["validation_ok"])

    def test_flow_accepts_mismatch_with_ping0_label(self):
        tempdir, output_path, summary_path, details_path, outcome = self.run_flow(
            [
                ("1.1.1.1:443", "SG", "SG", "HK"),
                ("2.2.2.2:443", "JP", "JP", "JP"),
                ("3.3.3.3:443", "US", "US", "US"),
            ],
            mismatch_policy="ping0",
        )
        self.addCleanup(tempdir.cleanup)
        self.assertEqual(outcome, 0)
        output_lines = output_path.read_text(encoding="utf-8").splitlines()
        self.assertTrue(output_lines[0].endswith("#香港-1"))
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(summary["accepted_ping0_override_count"], 1)
        self.assertEqual(summary["dropped_mismatch_count"], 0)
        self.assertEqual(summary["provider_mismatch_policy"], "ping0")
        details = details_path.read_text(encoding="utf-8-sig")
        self.assertIn("accepted_ping0_override", details)

    def test_batch_fails_only_when_remaining_assets_miss_gate_and_keeps_diagnostics(self):
        tempdir, _output_path, summary_path, details_path, outcome = self.run_flow(
            [
                ("1.1.1.1:443", "SG", "SG", "SG"),
                ("2.2.2.2:443", "JP", "JP", "JP"),
                ("3.3.3.3:443", "US", "", "US"),
            ],
            min_lines=3,
            min_regions=2,
        )
        self.addCleanup(tempdir.cleanup)
        self.assertIsInstance(outcome, SystemExit)
        self.assertTrue(summary_path.exists())
        self.assertTrue(details_path.exists())
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(summary["verified_count"], 2)
        self.assertFalse(summary["validation_ok"])


if __name__ == "__main__":
    unittest.main()
