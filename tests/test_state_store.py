import tempfile
import unittest
from pathlib import Path

import scheduler
from state_store import StateStore


TEMPLATE = {
    "name": "test",
    "type": "vless",
    "server": "example.com",
    "port": 443,
    "uuid": "00000000-0000-0000-0000-000000000000",
    "network": "ws",
    "servername": "example.com",
    "ws-opts": {"path": "/", "headers": {"Host": "example.com"}},
}


class StateStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "state.sqlite"
        self.store = StateStore(self.db)
        self.candidate_id, _, _ = self.store.upsert_candidate(
            host="198.51.100.1", port=443, template_proxy=TEMPLATE
        )

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def apply(self, run_id, status="confirmed_non_hk", country="SG", latency_ok=True, samples=3):
        return self.store.apply_strict_result(
            candidate_id=self.candidate_id,
            run_id=run_id,
            decision_status=status,
            country=country,
            exit_ip="203.0.113.9",
            latency_ok=latency_ok,
            latency_median_ms=100 if latency_ok else None,
            latency_p90_ms=120 if latency_ok else None,
            latency_sample_count=samples if latency_ok else 0,
        )

    def row(self):
        return self.store.rows("c.candidate_id=?", (self.candidate_id,))[0]

    def test_two_independent_non_hk_runs_promote_to_hot(self):
        self.assertEqual("probation", self.apply(1))
        self.assertEqual("probation", self.apply(1))
        self.assertEqual(1, self.row()["country_success_streak"])
        self.assertEqual(1, self.row()["strict_success_count"])
        self.assertEqual("hot", self.apply(2))
        self.assertEqual(2, self.row()["country_success_streak"])
        self.assertTrue(scheduler.is_publishable(self.row()))

    def test_hk_history_requires_three_non_hk_recovery_runs(self):
        self.apply(1, "confirmed_hk", "HK")
        self.assertEqual("probation", self.apply(2, country="SG"))
        self.assertEqual("probation", self.apply(3, country="SG"))
        self.assertEqual("hot", self.apply(4, country="SG"))
        self.assertEqual(3, self.row()["country_success_streak"])
        self.assertEqual(1, self.row()["hk_seen_count"])

    def test_mismatch_clears_country_and_is_not_publishable(self):
        self.apply(1)
        self.apply(2)
        self.apply(3, "geo_mismatch", None, latency_ok=False, samples=0)
        row = self.row()
        self.assertEqual("geo_mismatch", row["state"])
        self.assertIsNone(row["assigned_country"])
        self.assertFalse(scheduler.is_publishable(row))

    def test_current_latency_failure_cannot_publish_using_old_samples(self):
        self.apply(1)
        self.apply(2)
        self.assertTrue(scheduler.is_publishable(self.row()))
        self.apply(3, latency_ok=False, samples=0)
        row = self.row()
        self.assertEqual("cooldown", row["state"])
        self.assertFalse(scheduler.is_publishable(row))

    def test_mark_published_does_not_turn_failed_old_active_into_hot(self):
        first_run = self.store.start_run("wednesday", "youtube_ping0_strict_v1")
        second_run = self.store.start_run("wednesday", "youtube_ping0_strict_v1")
        self.apply(first_run)
        self.apply(second_run)
        self.store.mark_published(
            run_id=second_run,
            selections=[(self.candidate_id, "SG", "新加坡", 1)],
            artifact_sha256="A" * 64,
        )
        third_run = self.store.start_run("wednesday", "youtube_ping0_strict_v1")
        self.apply(third_run, "geo_mismatch", None, latency_ok=False, samples=0)
        self.store.mark_published(run_id=third_run, selections=[], artifact_sha256="B" * 64)
        self.assertEqual("geo_mismatch", self.row()["state"])

    def test_finalize_publish_is_idempotent(self):
        run_id = self.store.start_run("wednesday", "youtube_ping0_strict_v1")
        self.apply(run_id)
        second_run = self.store.start_run("wednesday", "youtube_ping0_strict_v1")
        self.apply(second_run)
        self.store.finish_run(second_run, result="staged", artifact_sha256="C" * 64)
        selections = [(self.candidate_id, "SG", "新加坡", 1)]
        self.store.finalize_publish(run_id=second_run, selections=selections, artifact_sha256="C" * 64)
        self.store.finalize_publish(run_id=second_run, selections=selections, artifact_sha256="C" * 64)
        count = self.store.connection.execute(
            "SELECT COUNT(*) FROM publish_history WHERE run_id=?", (second_run,)
        ).fetchone()[0]
        self.assertEqual(1, count)
        self.assertTrue(self.row()["published"])


if __name__ == "__main__":
    unittest.main()
