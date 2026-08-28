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


class Page(list):
    """Rows, and whether they are all of the rows.

    Every estate route reads the whole estate through one of the `all_*`
    queries, each of which carries a LIMIT. Measured on a 100-collector fleet
    with 120 devices per ring: 12,000 assets in the database, 5,000 returned,
    7,000 silently absent — and 20,000 of 40,000 flows likewise. The console
    rendered a confident inventory of exactly 5,000 devices with nothing
    anywhere to say it was a fraction.

    That is the same failure this system has now made four times: a switched-off
    collector counted as healthy, an unassessed asset reported clean, an
    unreadable transport reported as a quiet network, and now a truncated
    inventory reported as an inventory. Every one of them a confident number
    over a question nobody asked.

    The ORDER BY makes it worse rather than better. Rows come back
    `last_seen DESC`, so truncation discards the LEAST recently seen first — and
    on a distribution network the quietest device is an FRTU on a ring main unit
    that only transmits on a fault. The rows dropped first are the ones most
    worth having.

    So a query returns a Page. It is a list, so every existing caller keeps
    working, and it carries `total` so no caller can claim completeness it was
    never given. `complete` is the property routes are expected to surface, in
    exactly the way OTS-CON-004 makes a count carry its coverage.
    """

    def __init__(self, rows, total=None, limit=None):
        super().__init__(rows)
        #: Rows matching the query, ignoring the limit. None when not counted.
        self.total = total
        self.limit = limit

    @property
    def complete(self) -> bool:
        """False when rows were left behind. `None` total means unknown, which
        is NOT complete — same asymmetry as Coverage.UNKNOWN."""
        if self.total is None:
            return False
        return len(self) >= self.total

    @property
    def missing(self) -> int:
        return max(0, (self.total or 0) - len(self))

    def explain(self) -> str:
        if self.complete:
            return ""
        return ("showing %d of %d — %d row(s) were not read because the query "
                "limit is %s. The rows omitted are the least recently seen, "
                "which on an OT network are the devices that speak rarely."
                % (len(self), self.total or 0, self.missing, self.limit))


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

    def _count(self, table: str) -> int:
        """How many rows the query WOULD have returned without its limit.

        A second query rather than a window function: measured at 0.05s over
        12,000 rows, and it keeps the row-building SQL exactly as it was.
        """
        with self.conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM " + table)
            return int(cur.fetchone()[0])

    def all_assets(self, limit: int = 5000) -> Page:
        """Every collector's asset rows, for the estate merge.

        Returns a Page, so a route cannot present this as the whole estate
        without being told whether it is. See Page for what that cost at a
        100-collector fleet.
        """
        return Page(self.assets(collector_id=None, limit=limit),
                    total=self._count("asset"), limit=limit)

    def all_flows(self, limit: int = 20000) -> Page:
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
            rows = [{"flow_key": r[0], "collector_id": r[1],
                     "first_seen": r[2], "last_seen": r[3],
                     "observation_count": r[4], "attributes": r[5]}
                    for r in cur.fetchall()]
        return Page(rows, total=self._count("flow"), limit=limit)

    def collectors_health(self) -> List[Dict]:
        """Every collector row, for the fleet health assessment.

        Includes `last_heartbeat`, which is the column the coverage model never
        looked at — and the reason a switched-off collector could report a clean
        plant indefinitely.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT collector_id, site, last_heartbeat, capture_state, "
                "queue_depth, rulepack_version, enabled, collector_version "
                "FROM collector ORDER BY collector_id")
            return [{"collector_id": r[0], "site": r[1], "last_heartbeat": r[2],
                     "capture_state": r[3], "queue_depth": r[4],
                     "rulepack_version": r[5], "enabled": r[6],
                     "collector_version": r[7]} for r in cur.fetchall()]

    # ── content packs (Phase 6) ───────────────────────────────────────────

    def publish_pack(self, pack, published_by: str = "") -> None:
        """Store a signed pack. The primary key refuses a duplicate version,
        which is the point: two different packs claiming the same version would
        make "which content produced this" unanswerable."""
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO content_pack (kind, version, digest, signature, "
                "payload, published_by) VALUES (%s, %s, %s, %s, %s, %s)",
                (pack.kind, pack.version, pack.digest, pack.signature,
                 _json(pack.payload), published_by))
        self.conn.commit()

    def latest_pack(self, kind: str) -> Optional[Dict]:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT kind, version, created_at, digest, signature, payload, "
                "published_by FROM content_pack WHERE kind = %s "
                "ORDER BY version DESC LIMIT 1", (kind,))
            row = cur.fetchone()
        return _pack_row(row)

    def latest_pack_version(self, kind: str) -> int:
        with self.conn.cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(version), 0) FROM content_pack "
                        "WHERE kind = %s", (kind,))
            return int(cur.fetchone()[0])

    def packs(self, kind: Optional[str] = None) -> List[Dict]:
        sql = ("SELECT kind, version, created_at, digest, signature, payload, "
               "published_by FROM content_pack")
        params: List[Any] = []
        if kind:
            sql += " WHERE kind = %s"
            params.append(kind)
        sql += " ORDER BY kind, version DESC"
        with self.conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            return [_pack_row(row) for row in cur.fetchall()]

    def reported_pack_versions(self) -> Dict[str, Any]:
        """What each collector last said it was running, from its heartbeat.

        A collector that has never reported one appears with None rather than 0:
        "has not told us" and "is running version 0" are different states, and
        only one of them is a collector to go and look at.
        """
        with self.conn.cursor() as cur:
            cur.execute("SELECT collector_id, rulepack_version FROM collector")
            out = {}
            for collector_id, version in cur.fetchall():
                try:
                    out[collector_id] = int(version) if version else None
                except (TypeError, ValueError):
                    out[collector_id] = None
            return out

    # ── operators, sessions and second factors (OTS-SRV-006) ──────────────

    def operator_count(self) -> int:
        """How many operators exist. The bootstrap asks, and asks only once."""
        with self.conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM operator")
            return int(cur.fetchone()[0])

    def create_operator(self, username: str, password_hash: str,
                        display_name: str = "") -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO operator (username, display_name, password_hash) "
                "VALUES (%s, %s, %s)",
                (username.strip().lower(), display_name, password_hash))
        self.conn.commit()

    def operator(self, username: str) -> Optional[Dict]:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT username, display_name, password_hash, status, "
                "last_login_at FROM operator WHERE username = %s",
                ((username or "").strip().lower(),))
            row = cur.fetchone()
        if row is None:
            return None
        return {"username": row[0], "display_name": row[1],
                "password_hash": row[2], "status": row[3],
                "last_login_at": row[4]}

    def set_operator_password(self, username: str, password_hash: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE operator SET password_hash = %s, updated_at = now() "
                "WHERE username = %s", (password_hash, username))
        self.conn.commit()

    def note_operator_login(self, username: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute("UPDATE operator SET last_login_at = now() "
                        "WHERE username = %s", (username,))
        self.conn.commit()

    # sessions
    def open_session(self, token_hash: str, username: str, window) -> None:
        import datetime

        def stamp(value):
            return datetime.datetime.fromtimestamp(
                value, datetime.timezone.utc)

        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO operator_session (token_hash, username, "
                "issued_at, expires_at, absolute_deadline) "
                "VALUES (%s, %s, %s, %s, %s)",
                (token_hash, username, stamp(window.issued_at),
                 stamp(window.expires_at), stamp(window.absolute_deadline)))
        self.conn.commit()

    def session(self, token_hash: str) -> Optional[Dict]:
        """A live session, or None.

        Expiry is evaluated in the STATEMENT rather than in Python: a row that
        has aged out must never come back, whatever the caller then does with
        it.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT s.token_hash, s.username, s.issued_at, s.expires_at, "
                "s.absolute_deadline, o.status, o.display_name "
                "FROM operator_session s JOIN operator o "
                "ON o.username = s.username "
                "WHERE s.token_hash = %s AND s.expires_at > now() "
                "AND s.absolute_deadline > now()", (token_hash,))
            row = cur.fetchone()
        if row is None:
            return None
        return {"token_hash": row[0], "username": row[1], "issued_at": row[2],
                "expires_at": row[3], "absolute_deadline": row[4],
                "status": row[5], "display_name": row[6]}

    def touch_session(self, token_hash: str, expires_at) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE operator_session SET expires_at = LEAST(%s, "
                "absolute_deadline) WHERE token_hash = %s",
                (expires_at, token_hash))
        self.conn.commit()

    def close_session(self, token_hash: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM operator_session WHERE token_hash = %s",
                        (token_hash,))
        self.conn.commit()

    def close_all_sessions(self, username: str) -> int:
        """Every session for one operator. A password change that leaves the
        old sessions alive has changed nothing for whoever already had one."""
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM operator_session WHERE username = %s",
                        (username,))
            closed = cur.rowcount
        self.conn.commit()
        return closed

    # second factor
    def totp_state(self, username: str) -> Optional[Dict]:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT username, secret, enabled, last_counter, enrolled_at "
                "FROM operator_totp WHERE username = %s", (username,))
            row = cur.fetchone()
        if row is None:
            return None
        return {"username": row[0], "secret": row[1], "enabled": row[2],
                "last_counter": row[3], "enrolled_at": row[4]}

    def stage_totp_secret(self, username: str, secret: str) -> None:
        """A secret that is NOT yet in force. See operator_totp's comment."""
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO operator_totp (username, secret, enabled, "
                "last_counter, updated_at) VALUES (%s, %s, FALSE, -1, now()) "
                "ON CONFLICT (username) DO UPDATE SET secret = EXCLUDED.secret, "
                "enabled = FALSE, last_counter = -1, enrolled_at = NULL, "
                "updated_at = now()", (username, secret))
        self.conn.commit()

    def enable_totp(self, username: str, counter: int) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE operator_totp SET enabled = TRUE, last_counter = %s, "
                "enrolled_at = now(), updated_at = now() WHERE username = %s",
                (counter, username))
        self.conn.commit()

    def disable_totp(self, username: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM operator_totp WHERE username = %s",
                        (username,))
            cur.execute("DELETE FROM operator_recovery WHERE username = %s",
                        (username,))
        self.conn.commit()

    def record_totp_counter(self, username: str, counter: int) -> None:
        """The replay guard. Only ever moves forward."""
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE operator_totp SET last_counter = GREATEST(last_counter, "
                "%s), updated_at = now() WHERE username = %s",
                (counter, username))
        self.conn.commit()

    def store_recovery_codes(self, username: str,
                             fingerprints: List[str]) -> None:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM operator_recovery WHERE username = %s",
                        (username,))
            for fingerprint in fingerprints:
                cur.execute(
                    "INSERT INTO operator_recovery (username, fingerprint) "
                    "VALUES (%s, %s)", (username, fingerprint))
        self.conn.commit()

    def unused_recovery_fingerprints(self, username: str) -> List[str]:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT fingerprint FROM operator_recovery "
                "WHERE username = %s AND used_at IS NULL", (username,))
            return [row[0] for row in cur.fetchall()]

    def spend_recovery_code(self, username: str, fingerprint: str) -> bool:
        """Single use, claimed in one statement for the same reason an enrolment
        token is: check-then-use lets the same code be spent twice."""
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE operator_recovery SET used_at = now() "
                "WHERE username = %s AND fingerprint = %s AND used_at IS NULL",
                (username, fingerprint))
            claimed = cur.rowcount
        self.conn.commit()
        return bool(claimed)

    # ── enrolment and certificates (Phase 6) ──────────────────────────────

    def create_enrolment_token(self, minted) -> None:
        """Store a minted token by its hash. The plaintext never arrives here."""
        with self.conn.cursor() as cur:
            cur.execute(
                """INSERT INTO enrolment_token (token_hash, collector_id, site,
                       expires_at, allow_reissue)
                   VALUES (%s, %s, %s, %s, %s)""",
                (minted.token_hash, minted.collector_id, minted.site,
                 minted.expires_at, minted.allow_reissue))
        self.conn.commit()

    def redeem_enrolment_token(self, token_hash: str) -> Optional[Dict]:
        """Claim a token, exclusively, in ONE statement.

        Check-then-use is two statements, and a second request can pass the
        check between them. Two collectors would then hold valid certificates
        naming the same identity, both would report, and the console would show
        one collector whose inventory matches neither plant.

        The conditional UPDATE is the claim: a returned row means this caller
        redeemed it, and every other caller gets None. Expiry is evaluated in
        the same statement for the same reason.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                """UPDATE enrolment_token SET used_at = now()
                   WHERE token_hash = %s
                     AND used_at IS NULL
                     AND expires_at > now()
                   RETURNING collector_id, site, allow_reissue""",
                (token_hash,))
            row = cur.fetchone()
        self.conn.commit()
        if row is None:
            return None
        return {"collector_id": row[0], "site": row[1], "allow_reissue": row[2]}

    def release_enrolment_token(self, token_hash: str) -> bool:
        """Un-claim a token whose enrolment did not produce a certificate.

        The redemption is atomic so that a replay cannot pass a check a
        concurrent request has already passed. But claiming it and then refusing
        to issue — a malformed CSR, a collector that already holds a certificate
        — spends a one-time credential on a request that produced nothing, and
        the engineer standing at the cabinet has to go back to an operator for
        another one.

        Released ONLY while `used_serial` is empty. A token that produced a
        certificate stays spent forever, whatever else happens afterwards.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE enrolment_token SET used_at = NULL "
                "WHERE token_hash = %s AND used_serial = ''", (token_hash,))
            changed = cur.rowcount
        self.conn.commit()
        return bool(changed)

    def record_token_serial(self, token_hash: str, serial: str) -> None:
        """Which certificate a token produced. Kept so an issued identity can be
        traced back to the person who authorised it."""
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE enrolment_token SET used_serial = %s WHERE token_hash = %s",
                (serial, token_hash))
        self.conn.commit()

    def record_certificate(self, issued) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                """INSERT INTO certificate (serial, collector_id, subject,
                       fingerprint, not_before, not_after)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (issued.serial, issued.collector_id, issued.subject,
                 issued.fingerprint, issued.not_before, issued.not_after))
        self.conn.commit()

    def certificate_by_fingerprint(self, fingerprint: str) -> Optional[Dict]:
        """The record every authenticated request is checked against.

        Returned whether or not it is revoked or expired: the caller must be
        able to say WHY an identity was refused, and "unknown certificate" and
        "revoked certificate" are different events for whoever reads the log.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT serial, collector_id, subject, fingerprint, not_before, "
                "not_after, revoked_at, revocation_reason FROM certificate "
                "WHERE fingerprint = %s", (fingerprint,))
            row = cur.fetchone()
        return _certificate_row(row)

    def active_certificates(self, collector_id: str) -> List[Dict]:
        """Unrevoked and unexpired certificates held by one collector."""
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT serial, collector_id, subject, fingerprint, not_before, "
                "not_after, revoked_at, revocation_reason FROM certificate "
                "WHERE collector_id = %s AND revoked_at IS NULL "
                "AND not_after > now() ORDER BY not_after DESC",
                (collector_id,))
            rows = cur.fetchall()
        return [_certificate_row(row) for row in rows]

    def certificates(self, collector_id: Optional[str] = None) -> List[Dict]:
        sql = ("SELECT serial, collector_id, subject, fingerprint, not_before, "
               "not_after, revoked_at, revocation_reason FROM certificate")
        params: List[Any] = []
        if collector_id:
            sql += " WHERE collector_id = %s"
            params.append(collector_id)
        sql += " ORDER BY not_after DESC"
        with self.conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [_certificate_row(row) for row in rows]

    def revoke_certificate(self, serial: str, reason: str) -> bool:
        """Revoke, once. Re-revoking does not overwrite the original reason or
        timestamp — the first revocation is the one that happened."""
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE certificate SET revoked_at = now(), "
                "revocation_reason = %s WHERE serial = %s AND revoked_at IS NULL",
                (reason, serial))
            changed = cur.rowcount
        self.conn.commit()
        return bool(changed)

    def all_detections(self, limit: int = 20000) -> Page:
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
                # NOT `ORDER BY severity`: it is TEXT, so the ordering is
                # alphabetical — 'medium' before 'low' before 'high' — and the
                # LIMIT would then drop the high-severity rows first while
                # looking like it had kept the important ones.
                "FROM detection ORDER BY last_seen DESC NULLS LAST LIMIT %s",
                (limit,))
            rows = [{"detection_key": r[0], "collector_id": r[1],
                     "asset_key": r[2], "rule_id": r[3], "severity": r[4],
                     "last_coverage": r[5], "rulepack_version": r[6],
                     "attributes": r[7]} for r in cur.fetchall()]
        return Page(rows, total=self._count("detection"), limit=limit)


def _pack_row(row) -> Optional[Dict]:
    if row is None:
        return None
    return {"kind": row[0], "version": int(row[1]), "created_at": row[2],
            "digest": row[3], "signature": row[4], "payload": row[5],
            "published_by": row[6]}


def _certificate_row(row) -> Optional[Dict]:
    if row is None:
        return None
    return {"serial": row[0], "collector_id": row[1], "subject": row[2],
            "fingerprint": row[3], "not_before": row[4], "not_after": row[5],
            "revoked_at": row[6], "revocation_reason": row[7]}


def _json(value: Any) -> str:
    import json

    return json.dumps(value, separators=(",", ":"), default=str)
