import datetime as dt
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import bestcf_tool as tool
import geo_policy
from state_store import StateStore


def load_script(name, filename):
    path = Path(__file__).resolve().parents[1] / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


stateful_update = load_script("stateful_update_test", "stateful-update.py")
finalize_publish = load_script("finalize_publish_test", "finalize-publish.py")


class StatefulUpdateTests(unittest.TestCase):
    def test_wednesday_only_carries_fully_verified_published_hk(self):
        class FakeStore:
            def rows(self):
                return [
                    {
                        "assigned_country": "HK", "published": 1,
                        "last_decision_status": "confirmed_hk", "latency_sample_count": 0,
                        "last_run_id": 1,
                    },
                    {
                        "assigned_country": "HK", "published": 1,
                        "last_decision_status": "confirmed_hk", "latency_sample_count": 3,
                        "last_run_id": 1,
                    },
                ]

        rows = stateful_update.current_run_publishable_rows(FakeStore(), run_id=2, mode="wednesday")
        self.assertEqual(1, len(rows))
        self.assertEqual(3, rows[0]["latency_sample_count"])

    def test_preflight_requires_fresh_cn_report(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "preflight.json"
            report = {
                "ok": True,
                "trace": {"loc": "CN"},
                "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            }
            path.write_text(json.dumps(report), encoding="utf-8")
            stateful_update.verify_preflight(path, max_age_minutes=15)
            report["generated_at"] = (dt.datetime.now().astimezone() - dt.timedelta(hours=1)).isoformat()
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "stale"):
                stateful_update.verify_preflight(path, max_age_minutes=15)

    def test_latency_batch_guard_rejects_global_failure(self):
        candidate = tool.Candidate("test", "198.51.100.1:443", "198.51.100.1", 443, "test")
        failed = {
            (f"198.51.100.{index}", 443): tool.TestResult(candidate, False, "latency_failed")
            for index in range(10)
        }
        with self.assertRaisesRegex(RuntimeError, "latency environment"):
            stateful_update.guard_latency_batch(failed)

    def test_full_latency_requires_all_three_samples(self):
        self.assertEqual(3, stateful_update.required_valid_latency_samples(3))
        self.assertEqual(1, stateful_update.required_valid_latency_samples(1))

    def test_finalize_manifest_matches_database_and_artifact_exactly(self):
        template = {
            "type": "vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "servername": "example.com",
            "ws-opts": {"path": "/", "headers": {"Host": "example.com"}},
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "bestcf_final.txt"
            payload = "198.51.100.1:443#新加坡-1\n"
            artifact.write_text(payload, encoding="utf-8", newline="\n")
            sha = hashlib.sha256(payload.encode("utf-8")).hexdigest().upper()
            with StateStore(root / "state.sqlite") as store:
                candidate_id, fingerprint, _ = store.upsert_candidate(
                    host="198.51.100.1", port=443, template_proxy=template
                )
                first = store.start_run("wednesday", geo_policy.POLICY_VERSION)
                second = store.start_run("wednesday", geo_policy.POLICY_VERSION)
                for run_id in (first, second):
                    store.apply_strict_result(
                        candidate_id=candidate_id,
                        run_id=run_id,
                        decision_status="confirmed_non_hk",
                        country="SG",
                        exit_ip="203.0.113.1",
                        latency_ok=True,
                        latency_median_ms=100,
                        latency_p90_ms=120,
                        latency_sample_count=3,
                    )
                store.finish_run(second, result="staged", artifact_sha256=sha)
                manifest = {
                    "manifest_version": 1,
                    "run_id": second,
                    "effective_mode": "wednesday",
                    "policy_version": geo_policy.POLICY_VERSION,
                    "artifact_sha256": sha,
                    "selected": [{
                        "candidate_id": candidate_id,
                        "fingerprint": fingerprint,
                        "endpoint": "198.51.100.1:443",
                        "country": "SG",
                        "label": "新加坡",
                        "rank": 1,
                    }],
                }
                selections = finalize_publish.validate_manifest(store, manifest, artifact)
                self.assertEqual([(candidate_id, "SG", "新加坡", 1)], selections)
                artifact.write_text("198.51.100.1:443#新加坡-2\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    finalize_publish.validate_manifest(store, manifest, artifact)


if __name__ == "__main__":
    unittest.main()
