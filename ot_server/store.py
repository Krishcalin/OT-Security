"""
PostgreSQL persistence (Q1).

Thin on purpose. Every decision about what the server believes lives in
`ingest.py`, which is pure and testable anywhere; this module only writes what
was decided. That split is what keeps the SQL short enough to read and the rules
exercisable without a database.

`psycopg` is imported inside `connect()` rather than at module scope, so the
schema, the queries and the API surface can be inspected and tested on a machine
with no driver installed — the same seam used for scapy in the collector and for
the same reason.

UPSERT, NOT INSERT
──────────────────
An asset seen in a hundred windows is one row with a count of a hundred, not a
hundred rows. `first_seen` is preserved with LEAST so a merge never moves an
asset's discovery date forward — recomputing it from arrival time would turn a
device present for a year into one discovered today, which is exactly the signal
an operator watches for.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import schema


class StoreError(RuntimeError):
    pass


def connect(dsn: str):
    """A PostgreSQL connection. Raises clearly when the driver is absent."""
    try:
        import psycopg
    except ImportError as exc:                             # pragma: no cover
        raise StoreError(
            "psycopg is required for the analysis server (Q1: PostgreSQL "
            "only). pip install 'psycopg[binary]'") from exc
    return psycopg.connect(dsn)


class Store:
    """Everything the ingest path writes and the API reads."""

    def __init__(self, conn):
        self.conn = conn

    # ── schema ────────────────────────────────────────────────────────────
    def migrate(self) -> int:
        with self.conn.cursor() as cur:
            for statement in schema.DDL:
                cur.execute(statement)
            cur.execute(
                "INSERT INTO schema_version (version) VALUES (%s) "
                "ON CONFLICT (version) DO NOTHING", (schema.SCHEMA_VERSION,))
        self.conn.commit()
        return schema.SCHEMA_VERSION

    def prune(self) -> None:
        """Apply the 13-month retention (Q5b)."""
        with self.conn.cursor() as cur:
            for statement in schema.PRUNE:
                cur.execute(statement)
        self.conn.commit()

    # ── collectors ────────────────────────────────────────────────────────
    def ensure_collector(self, collector_id: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO collector (collector_id) VALUES (%s) "
                "ON CONFLICT (collector_id) DO NOTHING", (collector_id,))

    def record_heartbeat(self, payload: Dict[str, Any]) -> None:
        self.ensure_collector(payload["collector_id"])
        health = payload.get("capture_health") or {}
        with self.conn.cursor() as cur:
            cur.execute(
                """UPDATE collector SET last_heartbeat = now(),
                       collector_version = %s, rulepack_version = %s,
                       capture_state = %s, queue_depth = %s
                   WHERE collector_id = %s""",
                (payload.get("collector_version", ""),
                 payload.get("rulepack_version", ""),
                 str(health.get("state", "unknown")),
                 int(payload.get("queue_depth") or 0),
                 payload["collector_id"]))
        self.conn.commit()

    # ── ingest ────────────────────────────────────────────────────────────
    def has_batch(self, batch_id: str) -> bool:
        with self.conn.cursor() as cur:
            cur.execute("SELECT 1 FROM batch WHERE batch_id = %s", (batch_id,))
            return cur.fetchone() is not None

    def write_batch(self, decision, window: Optional[Dict] = None) -> None:
        """Persist one accepted batch. One transaction: a batch recorded whose
        records failed to land would be answered 409 on the retry and lost."""
        self.ensure_collector(decision.collector_id)
        window = window or {}
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO batch (batch_id, collector_id, window_id, "
                "record_count) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (batch_id) DO NOTHING",
                (decision.batch_id, decision.collector_id, decision.window_id,
                 len(decision.records)))
            cur.execute(
                """INSERT INTO observation_window
                       (collector_id, window_id, started_at, ended_at, coverage,
                        packets_analysed, packets_lost, observed_fraction)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (collector_id, window_id) DO UPDATE SET
                       coverage = EXCLUDED.coverage,
                       packets_analysed = EXCLUDED.packets_analysed,
                       packets_lost = EXCLUDED.packets_lost,
                       observed_fraction = EXCLUDED.observed_fraction""",
                (decision.collector_id, decision.window_id,
                 window.get("started_at"), window.get("ended_at"),
                 decision.coverage,
                 int(window.get("packets_analysed") or 0),
                 window.get("packets_lost"), window.get("observed_fraction")))

            for record in decision.records:
                self._write_record(cur, decision, record)
        self.conn.commit()

    def _write_record(self, cur, decision, record: Dict) -> None:
        kind = record.get("kind")
        attrs = record.get("attributes") or {}
        prov = record.get("provenance") or {}
        common = (record.get("first_seen"), record.get("last_seen"),
                  int(record.get("observation_count") or 0),
                  decision.window_id, decision.coverage)

        if kind == "asset":
            cur.execute(
                """INSERT INTO asset (asset_key, collector_id, first_seen,
                       last_seen, observation_count, last_observed_window,
                       last_coverage, attributes)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (asset_key, collector_id) DO UPDATE SET
                       first_seen = LEAST(asset.first_seen,
                                          EXCLUDED.first_seen),
                       last_seen = GREATEST(asset.last_seen,
                                            EXCLUDED.last_seen),
                       observation_count = EXCLUDED.observation_count,
                       last_observed_window = EXCLUDED.last_observed_window,
                       last_coverage = EXCLUDED.last_coverage,
                       attributes = EXCLUDED.attributes,
                       updated_at = now()""",
                (record["key"], decision.collector_id) + common[:3]
                + common[3:] + (_json(attrs),))
        elif kind == "detection":
            cur.execute(
                """INSERT INTO detection (detection_key, collector_id,
                       asset_key, rule_id, severity, first_seen, last_seen,
                       observation_count, last_observed_window, last_coverage,
                       rulepack_version, attributes)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (detection_key, collector_id) DO UPDATE SET
                       first_seen = LEAST(detection.first_seen,
                                          EXCLUDED.first_seen),
                       last_seen = GREATEST(detection.last_seen,
                                            EXCLUDED.last_seen),
                       observation_count = EXCLUDED.observation_count,
                       last_observed_window = EXCLUDED.last_observed_window,
                       last_coverage = EXCLUDED.last_coverage,
                       rulepack_version = EXCLUDED.rulepack_version,
                       attributes = EXCLUDED.attributes,
                       updated_at = now()""",
                (record["key"], decision.collector_id,
                 str(attrs.get("asset", "")), str(attrs.get("rule_id", "")),
                 str(attrs.get("severity", "")),
                 record.get("first_seen"), record.get("last_seen"),
                 int(record.get("observation_count") or 0),
                 decision.window_id, decision.coverage,
                 str(prov.get("rulepack_version", "")), _json(attrs)))
        elif kind == "flow":
            cur.execute(
                """INSERT INTO flow (flow_key, collector_id, first_seen,
                       last_seen, observation_count, attributes)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT (flow_key, collector_id) DO UPDATE SET
                       first_seen = LEAST(flow.first_seen,
                                          EXCLUDED.first_seen),
                       last_seen = GREATEST(flow.last_seen,
                                            EXCLUDED.last_seen),
                       observation_count = EXCLUDED.observation_count,
                       attributes = EXCLUDED.attributes,
                       updated_at = now()""",
                (record["key"], decision.collector_id, record.get("first_seen"),
                 record.get("last_seen"),
                 int(record.get("observation_count") or 0), _json(attrs)))

    def write_gap(self, collector_id: str, gap: Dict) -> None:
        """A delivery gap is a record, not a log line (OTS-SRV-004)."""
        self.ensure_collector(collector_id)
        with self.conn.cursor() as cur:
            cur.execute(
                """INSERT INTO delivery_gap (collector_id, first_window,
                       last_window, since_epoch, until_epoch, batches_lost,
                       records_lost, reason)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (collector_id, str(gap.get("first_window", "")),
                 str(gap.get("last_window", "")), gap.get("since_epoch"),
                 gap.get("until_epoch"), int(gap.get("batches_lost") or 0),
                 int(gap.get("records_lost") or 0),
                 str(gap.get("reason", ""))))
        self.conn.commit()

    # ── reading ───────────────────────────────────────────────────────────
    def recent_windows(self, collector_id: str, limit: int = 50) -> List[Dict]:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT window_id, coverage, packets_analysed, packets_lost "
                "FROM observation_window WHERE collector_id = %s "
                "ORDER BY received_at DESC LIMIT %s", (collector_id, limit))
            return [{"window_id": r[0], "coverage": r[1],
                     "packets_analysed": r[2], "packets_lost": r[3]}
                    for r in cur.fetchall()]

    def recent_gaps(self, collector_id: str, limit: int = 50) -> List[Dict]:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT first_window, last_window, batches_lost, records_lost "
                "FROM delivery_gap WHERE collector_id = %s "
                "ORDER BY received_at DESC LIMIT %s", (collector_id, limit))
            return [{"first_window": r[0], "last_window": r[1],
                     "batches_lost": r[2], "records_lost": r[3]}
                    for r in cur.fetchall()]

    def latest_window(self, collector_id: str) -> str:
        windows = self.recent_windows(collector_id, limit=1)
        return windows[0]["window_id"] if windows else ""

    def assets(self, collector_id: Optional[str] = None,
               limit: int = 500) -> List[Dict]:
        sql = ("SELECT asset_key, collector_id, first_seen, last_seen, "
               "observation_count, last_observed_window, last_coverage, "
               "attributes FROM asset")
        params: List[Any] = []
        if collector_id:
            sql += " WHERE collector_id = %s"
            params.append(collector_id)
        sql += " ORDER BY last_seen DESC NULLS LAST LIMIT %s"
        params.append(limit)
        with self.conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            return [{"asset_key": r[0], "collector_id": r[1], "first_seen": r[2],
                     "last_seen": r[3], "observation_count": r[4],
                     "last_observed_window": r[5], "last_coverage": r[6],
                     "attributes": r[7]} for r in cur.fetchall()]

    # ── estate-wide reads (Phase 4) ───────────────────────────────────────
    def collector_sites(self) -> Dict[str, str]:
        """collector_id -> site. The scope every IP identity is merged within.

        A collector with no site recorded is returned as an empty string, which
        `estate.merge` maps to its own `<unassigned>` scope rather than folding
        it in with another unsited collector.
        """
        with self.conn.cursor() as cur:
            cur.execute("SELECT collector_id, site FROM collector")
            return {row[0]: row[1] or "" for row in cur.fetchall()}

    def collector_ids(self) -> List[str]:
        with self.conn.cursor() as cur:
            cur.execute("SELECT collector_id FROM collector ORDER BY collector_id")
            return [row[0] for row in cur.fetchall()]

    def set_site(self, collector_id: str, site: str) -> None:
        self.ensure_collector(collector_id)
        with self.conn.cursor() as cur:
            cur.execute("UPDATE collector SET site = %s WHERE collector_id = %s",
                        (site, collector_id))
        self.conn.commit()

    def all_assets(self, limit: int = 5000) -> List[Dict]:
        """Every collector's asset rows, for the estate merge."""
        return self.assets(collector_id=None, limit=limit)

    def all_flows(self, limit: int = 20000) -> List[Dict]:
        """Every collector's flow rows, for zone derivation and attack paths.

        The collector_id travels with the row and is not decoration: `zones.derive`
        attributes a flow to a site through it, and a flow that arrived without
        one lands in its own scope rather than being folded into a neighbouring
        plant.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT flow_key, collector_id, first_seen, last_seen, "
                "observation_count, attributes FROM flow "
                "ORDER BY last_seen DESC NULLS LAST LIMIT %s", (limit,))
            return [{"flow_key": r[0], "collector_id": r[1], "first_seen": r[2],
                     "last_seen": r[3], "observation_count": r[4],
                     "attributes": r[5]} for r in cur.fetchall()]

    def all_detections(self, limit: int = 20000) -> List[Dict]:
        """Every collector's detections, unfiltered.

        Deliberately not `WHERE asset_key = ANY(<keys the merge knows>)`. That
        query cannot return a detection whose asset row never arrived, so the
        count of orphans computed from it is always zero — a check that reports
        clean because it was structurally unable to look. The filtering happens
        after the merge, in `estate.reattach_detections`, where the (collector,
        key) pair is available and the orphans are visible.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT detection_key, collector_id, asset_key, rule_id, "
                "severity, last_coverage, rulepack_version, attributes "
                "FROM detection ORDER BY severity DESC LIMIT %s", (limit,))
            return [{"detection_key": r[0], "collector_id": r[1],
                     "asset_key": r[2], "rule_id": r[3], "severity": r[4],
                     "last_coverage": r[5], "rulepack_version": r[6],
                     "attributes": r[7]} for r in cur.fetchall()]


def _json(value: Any) -> str:
    import json

    return json.dumps(value, separators=(",", ":"), default=str)
