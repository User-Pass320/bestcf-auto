import datetime as dt
import unittest

import scheduler


def row(candidate_id, **overrides):
    value = {
        "candidate_id": candidate_id,
        "fingerprint": f"fp-{candidate_id}",
        "state": "new",
        "assigned_country": None,
        "legacy_country": None,
        "published": 0,
        "next_test_at": None,
        "last_tested_at": None,
        "last_decision_status": "",
        "strict_success_count": 0,
        "country_success_streak": 0,
        "hk_seen_count": 0,
        "latency_median_ms": None,
        "latency_p90_ms": None,
        "endpoint": f"198.51.100.{candidate_id}:443",
        "host": f"198.51.100.{candidate_id}",
        "canonical_exit_ip": f"203.0.113.{candidate_id}",
    }
    value.update(overrides)
    return value


class SchedulerTests(unittest.TestCase):
    def test_active_non_hk_runs_both_days_but_hk_only_sunday(self):
        rows = [
            row(1, state="active", assigned_country="SG", published=1),
            row(2, state="active", assigned_country="HK", published=1),
        ]
        wed = scheduler.build_test_plan(rows, mode="wednesday", day=dt.date(2026, 7, 22))
        sun = scheduler.build_test_plan(rows, mode="sunday", day=dt.date(2026, 7, 26))
        self.assertEqual([1], [int(item.row["candidate_id"]) for item in wed])
        self.assertEqual({1, 2}, {int(item.row["candidate_id"]) for item in sun})
        self.assertTrue(all(item.test_level == "full" for item in sun))

    def test_future_next_test_at_is_not_scheduled(self):
        rows = [
            row(1, state="hot", assigned_country="SG", next_test_at="2026-07-23T03:00:00+08:00"),
            row(2, state="hot", assigned_country="SG", next_test_at="2026-07-21T03:00:00+08:00"),
        ]
        plan = scheduler.build_test_plan(rows, mode="wednesday", day=dt.date(2026, 7, 22))
        self.assertEqual([2], [int(item.row["candidate_id"]) for item in plan])

    def test_cfst_two_port_rotation_covers_six_ports_in_three_weeks(self):
        sundays = [dt.date(2026, 7, 5), dt.date(2026, 7, 12), dt.date(2026, 7, 19)]
        groups = [scheduler.cfst_port_group(day) for day in sundays]
        self.assertEqual(3, len(set(groups)))
        self.assertEqual({443, 2053, 2083, 2087, 2096, 8443}, {port for group in groups for port in group})

    def test_cfst_rotation_does_not_repeat_at_year_boundary(self):
        sundays = [dt.date(2026, 12, 27), dt.date(2027, 1, 3), dt.date(2027, 1, 10)]
        groups = [scheduler.cfst_port_group(day) for day in sundays]
        self.assertEqual(3, len(set(groups)))

    def test_cold_four_shards_cover_every_candidate_across_two_weeks(self):
        rows = [row(index, state="cold", assigned_country="SG") for index in range(1, 101)]
        days = [
            ("wednesday", dt.date(2026, 7, 22)),
            ("sunday", dt.date(2026, 7, 26)),
            ("wednesday", dt.date(2026, 7, 29)),
            ("sunday", dt.date(2026, 8, 2)),
        ]
        selected = set()
        for mode, day in days:
            selected.update(int(item.row["candidate_id"]) for item in scheduler.build_test_plan(rows, mode=mode, day=day))
        self.assertEqual(set(range(1, 101)), selected)

    def test_cold_shards_continue_across_year_boundary(self):
        runs = [
            scheduler.cold_shard_index(dt.date(2026, 12, 30), "wednesday"),
            scheduler.cold_shard_index(dt.date(2027, 1, 3), "sunday"),
            scheduler.cold_shard_index(dt.date(2027, 1, 6), "wednesday"),
            scheduler.cold_shard_index(dt.date(2027, 1, 10), "sunday"),
        ]
        self.assertEqual(4, len(set(runs)))

    def test_publish_selection_uses_soft_host_sequence_and_exit_ip_cap(self):
        rows = []
        for index in range(1, 7):
            rows.append(
                row(
                    index,
                    state="hot",
                    assigned_country="SG",
                    last_decision_status="confirmed_non_hk",
                    strict_success_count=2,
                    country_success_streak=2,
                    latency_median_ms=index,
                    host="same.example",
                    endpoint=f"same.example:{440 + index}",
                    canonical_exit_ip="203.0.113.1" if index <= 4 else f"203.0.113.{index}",
                )
            )
        selected = scheduler.select_for_publish(rows, country_max=6, exit_ip_max=3)
        self.assertEqual(5, len(selected))
        self.assertEqual(5, sum(1 for item in selected if item["host"] == "same.example"))
        self.assertEqual(3, sum(1 for item in selected if item["canonical_exit_ip"] == "203.0.113.1"))


if __name__ == "__main__":
    unittest.main()
