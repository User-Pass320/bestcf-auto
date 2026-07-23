"""SQLite persistence for the stateful BestCF SelfDeploy pipeline."""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator


SCHEMA_VERSION = 2


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def template_identity(template_proxy: dict[str, Any]) -> dict[str, str]:
    ws_opts = template_proxy.get("ws-opts") if isinstance(template_proxy.get("ws-opts"), dict) else {}
    headers = ws_opts.get("headers") if isinstance(ws_opts.get("headers"), dict) else {}
    uuid_value = str(template_proxy.get("uuid") or template_proxy.get("password") or "")
    sanitized = dict(template_proxy)
    sanitized.pop("name", None)
    sanitized.pop("server", None)
    sanitized.pop("port", None)
    if "uuid" in sanitized:
        sanitized["uuid"] = sha256_text(uuid_value)
    if "password" in sanitized:
        sanitized["password"] = sha256_text(uuid_value)
    return {
        "protocol": str(template_proxy.get("type") or ""),
        "sni": str(template_proxy.get("servername") or template_proxy.get("sni") or ""),
        "ws_host": str(headers.get("Host") or headers.get("host") or ""),
        "path": str(ws_opts.get("path") or ""),
        "uuid_hash": sha256_text(uuid_value) if uuid_value else "",
        "template_hash": sha256_text(canonical_json(sanitized)),
    }


def candidate_fingerprints(host: str, port: int, template_proxy: dict[str, Any]) -> tuple[str, str, dict[str, str]]:
    identity = template_identity(template_proxy)
    common = {
        "protocol": identity["protocol"],
        "host": host.strip().lower(),
        "sni": identity["sni"],
        "ws_host": identity["ws_host"],
        "path": identity["path"],
        "uuid_hash": identity["uuid_hash"],
        "template_hash": identity["template_hash"],
    }
    fingerprint = sha256_text(canonical_json({**common, "port": int(port)}))
    family_fingerprint = sha256_text(canonical_json(common))
    return fingerprint, family_fingerprint, identity


SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
    candidate_id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    family_fingerprint TEXT NOT NULL,
    protocol TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    endpoint TEXT NOT NULL,
    sni TEXT NOT NULL DEFAULT '',
    ws_host TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    uuid_hash TEXT NOT NULL DEFAULT '',
    template_hash TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    raw_line TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    source_active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_candidates_endpoint ON candidates(host, port);
CREATE INDEX IF NOT EXISTS idx_candidates_family ON candidates(family_fingerprint);

CREATE TABLE IF NOT EXISTS candidate_state (
    candidate_id INTEGER PRIMARY KEY REFERENCES candidates(candidate_id) ON DELETE CASCADE,
    state TEXT NOT NULL DEFAULT 'new',
    baseline_candidate INTEGER NOT NULL DEFAULT 0,
    assigned_country TEXT,
    legacy_country TEXT,
    last_decision_status TEXT NOT NULL DEFAULT '',
    country_success_streak INTEGER NOT NULL DEFAULT 0,
    strict_success_count INTEGER NOT NULL DEFAULT 0,
    country_confidence REAL NOT NULL DEFAULT 0,
    hk_seen_count INTEGER NOT NULL DEFAULT 0,
    last_hk_seen_at TEXT,
    last_tested_at TEXT,
    last_success_at TEXT,
    next_test_at TEXT,
    success_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    consecutive_fail_count INTEGER NOT NULL DEFAULT 0,
    latency_median_ms REAL,
    latency_p90_ms REAL,
    latency_sample_count INTEGER NOT NULL DEFAULT 0,
    canonical_exit_ip TEXT,
    published INTEGER NOT NULL DEFAULT 0,
    last_published_at TEXT,
    last_run_id INTEGER,
    fail_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_state_country ON candidate_state(assigned_country, state);
CREATE INDEX IF NOT EXISTS idx_state_baseline ON candidate_state(baseline_candidate);

CREATE TABLE IF NOT EXISTS test_runs (
    run_id INTEGER PRIMARY KEY,
    run_mode TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    direct_preflight_ok INTEGER,
    policy_version TEXT NOT NULL,
    candidate_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    published_count INTEGER NOT NULL DEFAULT 0,
    result TEXT NOT NULL DEFAULT 'running',
    stage_timings_json TEXT NOT NULL DEFAULT '{}',
    artifact_sha256 TEXT
);

CREATE TABLE IF NOT EXISTS latency_observations (
    observation_id INTEGER PRIMARY KEY,
    run_id INTEGER REFERENCES test_runs(run_id),
    candidate_id INTEGER NOT NULL REFERENCES candidates(candidate_id) ON DELETE CASCADE,
    sample_index INTEGER,
    latency_ms REAL,
    median_ms REAL,
    p90_ms REAL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL,
    policy_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_latency_candidate ON latency_observations(candidate_id, observed_at);

CREATE TABLE IF NOT EXISTS geo_observations (
    observation_id INTEGER PRIMARY KEY,
    run_id INTEGER REFERENCES test_runs(run_id),
    candidate_id INTEGER NOT NULL REFERENCES candidates(candidate_id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    raw_country TEXT,
    normalized_country TEXT,
    exit_ip TEXT,
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL,
    policy_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_geo_candidate ON geo_observations(candidate_id, observed_at);

CREATE TABLE IF NOT EXISTS source_snapshots (
    source_name TEXT NOT NULL,
    source_url TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    fetch_status TEXT NOT NULL,
    candidate_count INTEGER NOT NULL DEFAULT 0,
    new_candidate_count INTEGER NOT NULL DEFAULT 0,
    non_hk_yield INTEGER NOT NULL DEFAULT 0,
    hk_yield INTEGER NOT NULL DEFAULT 0,
    failure_rate REAL NOT NULL DEFAULT 0,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY(source_name, fetched_at)
);

CREATE TABLE IF NOT EXISTS publish_history (
    publish_id INTEGER PRIMARY KEY,
    run_id INTEGER REFERENCES test_runs(run_id),
    candidate_id INTEGER NOT NULL REFERENCES candidates(candidate_id),
    published_country TEXT NOT NULL,
    label TEXT NOT NULL,
    rank INTEGER NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    published_at TEXT NOT NULL
);
"""


class StateStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript(SCHEMA)
        self._migrate_schema()
        self.connection.execute(
            "INSERT INTO metadata(key,value) VALUES('schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )
        self.connection.commit()

    def _migrate_schema(self) -> None:
        columns = {
            str(row[1])
            for row in self.connection.execute("PRAGMA table_info(candidate_state)")
        }
        if "next_test_at" not in columns:
            self.connection.execute("ALTER TABLE candidate_state ADD COLUMN next_test_at TEXT")
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_state_next_test ON candidate_state(state,next_test_at)"
        )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "StateStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc_type is None:
            self.connection.commit()
        else:
            self.connection.rollback()
        self.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            yield self.connection
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def set_metadata(self, key: str, value: Any) -> None:
        payload = value if isinstance(value, str) else canonical_json(value)
        self.connection.execute(
            "INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, payload),
        )

    def get_metadata(self, key: str, default: str | None = None) -> str | None:
        row = self.connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row else default

    def upsert_candidate(
        self,
        *,
        host: str,
        port: int,
        template_proxy: dict[str, Any],
        source: str = "",
        raw_line: str = "",
        first_seen_at: str | None = None,
        last_seen_at: str | None = None,
        source_active: bool = True,
    ) -> tuple[int, str, bool]:
        fingerprint, family, identity = candidate_fingerprints(host, port, template_proxy)
        timestamp = now_iso()
        first_seen = first_seen_at or timestamp
        last_seen = last_seen_at or timestamp
        existing = self.connection.execute(
            "SELECT candidate_id FROM candidates WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        created = existing is None
        self.connection.execute(
            """
            INSERT INTO candidates(
                fingerprint,family_fingerprint,protocol,host,port,endpoint,sni,ws_host,path,
                uuid_hash,template_hash,source,raw_line,first_seen_at,last_seen_at,source_active
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                source=CASE WHEN excluded.source<>'' THEN excluded.source ELSE candidates.source END,
                raw_line=CASE WHEN excluded.raw_line<>'' THEN excluded.raw_line ELSE candidates.raw_line END,
                last_seen_at=excluded.last_seen_at,
                source_active=excluded.source_active
            """,
            (
                fingerprint,
                family,
                identity["protocol"],
                host,
                int(port),
                f"[{host}]:{int(port)}" if ":" in host and not host.startswith("[") else f"{host}:{int(port)}",
                identity["sni"],
                identity["ws_host"],
                identity["path"],
                identity["uuid_hash"],
                identity["template_hash"],
                source,
                raw_line,
                first_seen,
                last_seen,
                1 if source_active else 0,
            ),
        )
        row = self.connection.execute(
            "SELECT candidate_id FROM candidates WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        candidate_id = int(row[0])
        self.connection.execute(
            "INSERT OR IGNORE INTO candidate_state(candidate_id,state,next_test_at) VALUES(?, 'new', ?)",
            (candidate_id, timestamp),
        )
        return candidate_id, fingerprint, created

    def candidate_by_fingerprint(self, fingerprint: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT c.*,s.* FROM candidates c JOIN candidate_state s USING(candidate_id) WHERE c.fingerprint=?",
            (fingerprint,),
        ).fetchone()

    def candidate_by_endpoint(self, host: str, port: int) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT c.*,s.* FROM candidates c JOIN candidate_state s USING(candidate_id) "
                "WHERE lower(c.host)=lower(?) AND c.port=?",
                (host, int(port)),
            )
        )

    def update_legacy_state(self, candidate_id: int, **fields: Any) -> None:
        allowed = {
            "state", "baseline_candidate", "assigned_country", "legacy_country", "last_decision_status",
            "country_success_streak", "strict_success_count", "country_confidence", "hk_seen_count",
            "last_hk_seen_at", "last_tested_at", "last_success_at", "next_test_at", "success_count",
            "fail_count", "consecutive_fail_count", "latency_median_ms", "latency_p90_ms",
            "latency_sample_count", "canonical_exit_ip", "published", "last_published_at", "fail_reason",
        }
        updates = {key: value for key, value in fields.items() if key in allowed}
        if not updates:
            return
        sql = ",".join(f"{key}=?" for key in updates)
        self.connection.execute(
            f"UPDATE candidate_state SET {sql} WHERE candidate_id=?",
            (*updates.values(), candidate_id),
        )

    def start_run(self, mode: str, policy_version: str, candidate_count: int = 0) -> int:
        cur = self.connection.execute(
            "INSERT INTO test_runs(run_mode,started_at,policy_version,candidate_count) VALUES(?,?,?,?)",
            (mode, now_iso(), policy_version, int(candidate_count)),
        )
        self.connection.commit()
        return int(cur.lastrowid)

    def finish_run(
        self,
        run_id: int,
        *,
        result: str,
        direct_preflight_ok: bool | None = None,
        success_count: int = 0,
        failure_count: int = 0,
        published_count: int = 0,
        stage_timings: dict[str, Any] | None = None,
        artifact_sha256: str | None = None,
    ) -> None:
        self.connection.execute(
            """
            UPDATE test_runs SET finished_at=?,direct_preflight_ok=?,success_count=?,failure_count=?,
                published_count=?,result=?,stage_timings_json=?,artifact_sha256=? WHERE run_id=?
            """,
            (
                now_iso(),
                None if direct_preflight_ok is None else int(direct_preflight_ok),
                int(success_count),
                int(failure_count),
                int(published_count),
                result,
                canonical_json(stage_timings or {}),
                artifact_sha256,
                int(run_id),
            ),
        )
        self.connection.commit()

    def record_geo_observation(
        self,
        *,
        candidate_id: int,
        provider: str,
        attempt: int,
        raw_country: str | None,
        normalized_country: str | None,
        exit_ip: str | None,
        status: str,
        policy_version: str,
        run_id: int | None = None,
        observed_at: str | None = None,
        error: str = "",
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO geo_observations(
                run_id,candidate_id,provider,attempt,raw_country,normalized_country,exit_ip,status,error,
                observed_at,policy_version
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                run_id, candidate_id, provider, int(attempt), raw_country, normalized_country, exit_ip,
                status, error, observed_at or now_iso(), policy_version,
            ),
        )

    def record_latency_observation(
        self,
        *,
        candidate_id: int,
        status: str,
        policy_version: str,
        run_id: int | None = None,
        sample_index: int | None = None,
        latency_ms: float | None = None,
        median_ms: float | None = None,
        p90_ms: float | None = None,
        sample_count: int = 0,
        observed_at: str | None = None,
        error: str = "",
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO latency_observations(
                run_id,candidate_id,sample_index,latency_ms,median_ms,p90_ms,sample_count,status,error,
                observed_at,policy_version
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                run_id, candidate_id, sample_index, latency_ms, median_ms, p90_ms, int(sample_count),
                status, error, observed_at or now_iso(), policy_version,
            ),
        )

    def record_source_snapshot(
        self,
        *,
        source_name: str,
        source_url: str,
        content_hash: str,
        fetch_status: str,
        candidate_count: int,
        new_candidate_count: int,
        fetched_at: str | None = None,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO source_snapshots(
                source_name,source_url,content_hash,fetch_status,candidate_count,new_candidate_count,fetched_at
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                source_name, source_url, content_hash, fetch_status, int(candidate_count),
                int(new_candidate_count), fetched_at or now_iso(),
            ),
        )

    def apply_strict_result(
        self,
        *,
        candidate_id: int,
        run_id: int,
        decision_status: str,
        country: str | None,
        exit_ip: str | None,
        latency_ok: bool,
        latency_median_ms: float | None,
        latency_p90_ms: float | None,
        latency_sample_count: int,
        fail_reason: str = "",
    ) -> str:
        current = self.connection.execute(
            "SELECT * FROM candidate_state WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        if current is None:
            raise KeyError(candidate_id)
        timestamp = now_iso()
        hk_seen = int(current["hk_seen_count"] or 0)
        streak = int(current["country_success_streak"] or 0)
        strict_count = int(current["strict_success_count"] or 0)
        success_count = int(current["success_count"] or 0)
        fail_count = int(current["fail_count"] or 0)
        consecutive_fail = int(current["consecutive_fail_count"] or 0)
        previous_country = str(current["assigned_country"] or "").upper() or None
        previous_decision = str(current["last_decision_status"] or "")
        same_run = int(current["last_run_id"] or 0) == int(run_id)
        assigned_country: str | None = country.upper() if country else None
        state: str
        last_success_at = current["last_success_at"]
        last_hk_seen_at = current["last_hk_seen_at"]
        next_test_at = (dt.datetime.now().astimezone() + dt.timedelta(hours=60)).isoformat(timespec="seconds")

        if decision_status == "confirmed_non_hk":
            if same_run and previous_decision == "confirmed_non_hk" and previous_country == assigned_country:
                pass
            elif previous_decision == "confirmed_non_hk" and previous_country == assigned_country:
                streak += 1
            else:
                streak = 1
            if not same_run:
                strict_count += 1
            required = 3 if hk_seen > 0 else 2
            if latency_ok:
                success_count += 1
                consecutive_fail = 0
                last_success_at = timestamp
                state = "hot" if streak >= required else "probation"
                fail_reason = ""
            else:
                fail_count += 1
                consecutive_fail += 1
                state = "cooldown"
                next_test_at = (dt.datetime.now().astimezone() + dt.timedelta(days=7)).isoformat(timespec="seconds")
        elif decision_status == "confirmed_hk":
            if not same_run:
                hk_seen += 1
            last_hk_seen_at = timestamp
            if same_run and previous_country == "HK" and previous_decision == "confirmed_hk":
                pass
            else:
                streak = streak + 1 if previous_country == "HK" and previous_decision == "confirmed_hk" else 1
                strict_count += 1
            assigned_country = "HK"
            if latency_ok:
                success_count += 1
                consecutive_fail = 0
                last_success_at = timestamp
                state = "hot"
                fail_reason = ""
            else:
                fail_count += 1
                consecutive_fail += 1
                state = "cooldown"
                next_test_at = (dt.datetime.now().astimezone() + dt.timedelta(days=7)).isoformat(timespec="seconds")
        elif decision_status == "hk_suspect":
            hk_seen += 1
            last_hk_seen_at = timestamp
            streak = 0
            assigned_country = None
            state = "hk_suspect"
            next_test_at = (dt.datetime.now().astimezone() + dt.timedelta(days=7)).isoformat(timespec="seconds")
        elif decision_status == "geo_mismatch":
            streak = 0
            assigned_country = None
            state = "geo_mismatch"
            next_test_at = (dt.datetime.now().astimezone() + dt.timedelta(days=7)).isoformat(timespec="seconds")
        elif decision_status == "geo_unknown":
            streak = 0
            assigned_country = None
            state = "geo_unknown"
            next_test_at = (dt.datetime.now().astimezone() + dt.timedelta(hours=60)).isoformat(timespec="seconds")
        else:
            fail_count += 1
            consecutive_fail += 1
            state = "cooldown" if consecutive_fail < 3 else "archive"
            retry_days = 7 if state == "cooldown" else 28
            next_test_at = (dt.datetime.now().astimezone() + dt.timedelta(days=retry_days)).isoformat(timespec="seconds")

        # A first strict non-HK observation must be eligible in the next distinct run.
        # The scheduled cadence itself supplies the wall-clock separation in production.
        if state == "probation":
            next_test_at = timestamp

        self.connection.execute(
            """
            UPDATE candidate_state SET state=?,assigned_country=?,last_decision_status=?,
                country_success_streak=?,strict_success_count=?,hk_seen_count=?,last_hk_seen_at=?,
                last_tested_at=?,last_success_at=?,success_count=?,fail_count=?,consecutive_fail_count=?,
                latency_median_ms=COALESCE(?,latency_median_ms),
                latency_p90_ms=COALESCE(?,latency_p90_ms),
                latency_sample_count=CASE WHEN ?>0 THEN ? ELSE latency_sample_count END,
                canonical_exit_ip=COALESCE(?,canonical_exit_ip),last_run_id=?,fail_reason=?,next_test_at=?
            WHERE candidate_id=?
            """,
            (
                state, assigned_country, decision_status, streak, strict_count, hk_seen, last_hk_seen_at,
                timestamp, last_success_at, success_count, fail_count, consecutive_fail,
                latency_median_ms, latency_p90_ms, int(latency_sample_count), int(latency_sample_count),
                exit_ip, int(run_id), fail_reason, next_test_at, candidate_id,
            ),
        )
        return state

    def rows(self, where: str = "1=1", params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT c.*,s.* FROM candidates c JOIN candidate_state s USING(candidate_id) "
                f"WHERE {where}",
                params,
            )
        )

    def counts(self) -> dict[str, Any]:
        total = int(self.connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[0])
        by_state = {
            str(row[0]): int(row[1])
            for row in self.connection.execute("SELECT state,COUNT(*) FROM candidate_state GROUP BY state")
        }
        by_country = {
            str(row[0] or "UNKNOWN"): int(row[1])
            for row in self.connection.execute(
                "SELECT assigned_country,COUNT(*) FROM candidate_state GROUP BY assigned_country"
            )
        }
        baseline = int(
            self.connection.execute("SELECT COUNT(*) FROM candidate_state WHERE baseline_candidate=1").fetchone()[0]
        )
        return {"total": total, "baseline": baseline, "by_state": by_state, "by_country": by_country}

    def mark_published(
        self,
        *,
        run_id: int,
        selections: list[tuple[int, str, str, int]],
        artifact_sha256: str,
    ) -> None:
        timestamp = now_iso()
        selected_ids = {candidate_id for candidate_id, _country, _label, _rank in selections}
        self.connection.execute(
            "UPDATE candidate_state SET published=0,"
            "state=CASE WHEN last_decision_status IN ('confirmed_non_hk','confirmed_hk') THEN 'hot' ELSE state END "
            "WHERE published=1"
        )
        if selected_ids:
            placeholders = ",".join("?" for _ in selected_ids)
            self.connection.execute(
                f"UPDATE candidate_state SET published=1,state='active',last_published_at=? "
                f"WHERE candidate_id IN ({placeholders})",
                (timestamp, *sorted(selected_ids)),
            )
        for candidate_id, country, label, rank in selections:
            self.connection.execute(
                """
                INSERT INTO publish_history(
                    run_id,candidate_id,published_country,label,rank,artifact_sha256,published_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (run_id, candidate_id, country, label, int(rank), artifact_sha256, timestamp),
            )

    def publish_already_finalized(self, run_id: int, artifact_sha256: str) -> bool:
        row = self.connection.execute(
            "SELECT COUNT(*) FROM publish_history WHERE run_id=? AND artifact_sha256=?",
            (int(run_id), artifact_sha256),
        ).fetchone()
        return bool(row and int(row[0]) > 0)

    def finalize_publish(
        self,
        *,
        run_id: int,
        selections: list[tuple[int, str, str, int]],
        artifact_sha256: str,
    ) -> None:
        with self.transaction():
            if self.publish_already_finalized(run_id, artifact_sha256):
                return
            run = self.connection.execute(
                "SELECT result,artifact_sha256 FROM test_runs WHERE run_id=?",
                (int(run_id),),
            ).fetchone()
            if run is None:
                raise KeyError(f"test run not found: {run_id}")
            if str(run["result"] or "") not in {"staged", "published"}:
                raise ValueError(f"test run is not staged for publication: {run['result']}")
            if str(run["artifact_sha256"] or "").upper() != artifact_sha256.upper():
                raise ValueError("run artifact SHA-256 does not match publish manifest")
            self.mark_published(
                run_id=run_id,
                selections=selections,
                artifact_sha256=artifact_sha256,
            )
            self.connection.execute(
                "UPDATE test_runs SET result='published',published_count=? WHERE run_id=?",
                (len(selections), int(run_id)),
            )
