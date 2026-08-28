"""
PostgreSQL schema for the analysis server (OTS-SRV-001, 004, 005; Q1).

PostgreSQL only, by decision Q1 — one dialect, one set of migrations. A SQLite
variant for single-site installs was considered and declined: every query and
migration would have to work on both forever, which is a tax paid on every
future change for a convenience felt once at install.

WHAT THE SHAPE IS FOR
─────────────────────
Three ideas drive it, and all three are about the difference between "we looked
and saw nothing" and "we did not look".

1. `observation_window` is the spine. Every record arrives attached to a window
   whose COVERAGE is known — complete, degraded, or unknown — and that coverage
   is stored, not summarised away. A finding from a degraded window is a weaker
   claim than one from a complete window, and the server must be able to say
   which.

2. `delivery_gap` records what never arrived. When a collector's spool fills
   during an outage it discards observations and reports the interval. Without
   this table the missing windows would be indistinguishable from a quiet
   network, and the collector's honesty would be discarded at the last step.

3. `asset` carries `last_observed_window`, never a deletion. An asset absent
   from the latest window is NOT OBSERVED, not gone (OTS-SRV-005): a passive
   sensor cannot tell a decommissioned device from one that simply did not
   speak, and deleting on absence would make a quiet PLC vanish from the
   inventory.

IDEMPOTENCY IS A UNIQUE CONSTRAINT
──────────────────────────────────
`batch(batch_id)` is unique. A replayed batch — the collector retrying after a
lost acknowledgement — collides and is answered 409 rather than double-counting
an asset (OTS-TRN-004). The database enforces it, not the application: two
ingest workers racing the same retry would otherwise both pass an application
check.
"""
from __future__ import annotations

from typing import Tuple

SCHEMA_VERSION = 3

DDL: Tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version      INTEGER PRIMARY KEY,
        applied_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS collector (
        collector_id       TEXT PRIMARY KEY,
        site               TEXT NOT NULL DEFAULT '',
        first_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_heartbeat     TIMESTAMPTZ,
        collector_version  TEXT NOT NULL DEFAULT '',
        rulepack_version   TEXT NOT NULL DEFAULT '',
        -- Health from the last heartbeat. Kept here rather than derived, so a
        -- collector that stops reporting keeps the last thing it said instead
        -- of appearing healthy by absence of news.
        capture_state      TEXT NOT NULL DEFAULT 'unknown',
        queue_depth        INTEGER NOT NULL DEFAULT 0,
        enabled            BOOLEAN NOT NULL DEFAULT TRUE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS batch (
        batch_id      TEXT PRIMARY KEY,
        collector_id  TEXT NOT NULL REFERENCES collector(collector_id),
        window_id     TEXT NOT NULL,
        received_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        record_count  INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS observation_window (
        collector_id      TEXT NOT NULL REFERENCES collector(collector_id),
        window_id         TEXT NOT NULL,
        started_at        DOUBLE PRECISION,
        ended_at          DOUBLE PRECISION,
        -- complete | degraded | unknown. Stored verbatim: collapsing it to a
        -- boolean would lose the distinction between measured-clean and
        -- not-measured, which is the distinction that matters.
        coverage          TEXT NOT NULL,
        packets_analysed  BIGINT NOT NULL DEFAULT 0,
        packets_lost      BIGINT,
        observed_fraction DOUBLE PRECISION,
        received_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (collector_id, window_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS delivery_gap (
        gap_id        BIGSERIAL PRIMARY KEY,
        collector_id  TEXT NOT NULL REFERENCES collector(collector_id),
        first_window  TEXT NOT NULL DEFAULT '',
        last_window   TEXT NOT NULL DEFAULT '',
        since_epoch   DOUBLE PRECISION,
        until_epoch   DOUBLE PRECISION,
        batches_lost  INTEGER NOT NULL DEFAULT 0,
        records_lost  INTEGER NOT NULL DEFAULT 0,
        reason        TEXT NOT NULL DEFAULT '',
        received_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS asset (
        asset_key             TEXT NOT NULL,
        collector_id          TEXT NOT NULL REFERENCES collector(collector_id),
        first_seen            DOUBLE PRECISION,
        last_seen             DOUBLE PRECISION,
        observation_count     BIGINT NOT NULL DEFAULT 0,
        -- OTS-SRV-005: absence is recorded, never acted on by deletion.
        last_observed_window  TEXT NOT NULL DEFAULT '',
        last_coverage         TEXT NOT NULL DEFAULT 'unknown',
        attributes            JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (asset_key, collector_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS detection (
        detection_key         TEXT NOT NULL,
        collector_id          TEXT NOT NULL REFERENCES collector(collector_id),
        asset_key             TEXT NOT NULL DEFAULT '',
        rule_id               TEXT NOT NULL DEFAULT '',
        severity              TEXT NOT NULL DEFAULT '',
        first_seen            DOUBLE PRECISION,
        last_seen             DOUBLE PRECISION,
        observation_count     BIGINT NOT NULL DEFAULT 0,
        last_observed_window  TEXT NOT NULL DEFAULT '',
        -- The coverage of the window this was derived from, and the rule pack
        -- that produced it. A finding that cannot name either is untraceable.
        last_coverage         TEXT NOT NULL DEFAULT 'unknown',
        rulepack_version      TEXT NOT NULL DEFAULT '',
        attributes            JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (detection_key, collector_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS flow (
        flow_key           TEXT NOT NULL,
        collector_id       TEXT NOT NULL REFERENCES collector(collector_id),
        first_seen         DOUBLE PRECISION,
        last_seen          DOUBLE PRECISION,
        observation_count  BIGINT NOT NULL DEFAULT 0,
        attributes         JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (flow_key, collector_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS enrolment_token (
        -- The PRIMARY KEY is the hash, because the plaintext is never stored.
        -- A copy of this database yields no working enrolment credential.
        token_hash    TEXT PRIMARY KEY,
        -- Fixed at mint time and never taken from the enrolment request: a
        -- collector that could name itself could enrol into another plant's
        -- site scope, and everything it reported would merge there.
        collector_id  TEXT NOT NULL,
        site          TEXT NOT NULL DEFAULT '',
        created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at    TIMESTAMPTZ NOT NULL,
        -- Set by the single conditional UPDATE that claims the token. Two
        -- statements here would let a replayed token be redeemed twice.
        used_at       TIMESTAMPTZ,
        used_serial   TEXT NOT NULL DEFAULT '',
        allow_reissue BOOLEAN NOT NULL DEFAULT FALSE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS certificate (
        serial            TEXT PRIMARY KEY,
        collector_id      TEXT NOT NULL,
        subject           TEXT NOT NULL,
        -- What every request is actually checked against. A subject is a name
        -- and names get reissued; the fingerprint identifies the one
        -- certificate that revocation revokes.
        fingerprint       TEXT NOT NULL UNIQUE,
        not_before        TIMESTAMPTZ NOT NULL,
        not_after         TIMESTAMPTZ NOT NULL,
        issued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
        revoked_at        TIMESTAMPTZ,
        revocation_reason TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS operator (
        username       TEXT PRIMARY KEY,
        display_name   TEXT NOT NULL DEFAULT '',
        -- pbkdf2_sha256$<iterations>$<salt>$<derived>. Self-describing, so
        -- raising the cost later is not a migration.
        password_hash  TEXT NOT NULL,
        status         TEXT NOT NULL DEFAULT 'active',
        created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_login_at  TIMESTAMPTZ
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS operator_session (
        -- The SHA-256 of the cookie, never the cookie. A copy of this database
        -- must not yield a working session.
        token_hash        TEXT PRIMARY KEY,
        username          TEXT NOT NULL REFERENCES operator(username)
                          ON DELETE CASCADE,
        issued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
        -- Slides forward on use...
        expires_at        TIMESTAMPTZ NOT NULL,
        -- ...but never past this, so a continuously-active session still
        -- forces a fresh sign-in eventually.
        absolute_deadline TIMESTAMPTZ NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS operator_totp (
        username     TEXT PRIMARY KEY REFERENCES operator(username)
                     ON DELETE CASCADE,
        secret       TEXT NOT NULL,
        -- Enrolment is two-step: a secret exists here before it is enabled,
        -- and is only switched on once a code it generated has been typed
        -- back. A one-step enable locks out anyone whose transcription was
        -- wrong -- and the person most likely to be hit is the first
        -- administrator, who has nobody to ask for a reset.
        enabled      BOOLEAN NOT NULL DEFAULT FALSE,
        -- The last counter accepted. A code stays valid for its whole step, so
        -- without this the same six digits replay for up to 90 seconds.
        last_counter BIGINT NOT NULL DEFAULT -1,
        enrolled_at  TIMESTAMPTZ,
        updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS operator_recovery (
        username    TEXT NOT NULL REFERENCES operator(username)
                    ON DELETE CASCADE,
        -- SHA-256 of the code. 50 bits of uniform randomness with no structure
        -- to guess at, so stretching buys nothing and would delay a login.
        fingerprint TEXT NOT NULL,
        used_at     TIMESTAMPTZ,
        PRIMARY KEY (username, fingerprint)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_session_username ON operator_session (username)",
    "CREATE INDEX IF NOT EXISTS ix_session_expiry ON operator_session (expires_at)",
    "CREATE INDEX IF NOT EXISTS ix_certificate_collector ON certificate (collector_id)",
    "CREATE INDEX IF NOT EXISTS ix_certificate_expiry ON certificate (not_after)",
    "CREATE INDEX IF NOT EXISTS ix_window_collector ON observation_window (collector_id, received_at DESC)",
    "CREATE INDEX IF NOT EXISTS ix_window_coverage ON observation_window (coverage)",
    "CREATE INDEX IF NOT EXISTS ix_asset_collector ON asset (collector_id)",
    "CREATE INDEX IF NOT EXISTS ix_detection_asset ON detection (asset_key)",
    "CREATE INDEX IF NOT EXISTS ix_detection_severity ON detection (severity)",
    "CREATE INDEX IF NOT EXISTS ix_gap_collector ON delivery_gap (collector_id, received_at DESC)",
)

#: Retention, per Q5b. Applied by a scheduled prune rather than at write time —
#: 13 months covers a full year of seasonal plant behaviour plus one, so a
#: year-on-year comparison always has both endpoints.
RETENTION_MONTHS = 13

PRUNE: Tuple[str, ...] = (
    "DELETE FROM observation_window WHERE received_at < now() - INTERVAL '%d months'"
    % RETENTION_MONTHS,
    "DELETE FROM batch WHERE received_at < now() - INTERVAL '%d months'"
    % RETENTION_MONTHS,
    "DELETE FROM delivery_gap WHERE received_at < now() - INTERVAL '%d months'"
    % RETENTION_MONTHS,
    # An expired, unredeemed token can never be used again, so keeping it is
    # keeping a hash of a credential for no reason. Redeemed ones stay: they are
    # the record of which token produced which certificate.
    "DELETE FROM enrolment_token WHERE used_at IS NULL "
    "AND expires_at < now() - INTERVAL '30 days'",
    # A session past its absolute deadline can never be honoured again, so the
    # row is a hash of a dead cookie and nothing more.
    "DELETE FROM operator_session WHERE absolute_deadline < now()",
)

#: Deliberately absent from PRUNE: `certificate`. What was issued, to whom, and
#: when it was revoked is the audit trail for the fleet's identities, and it has
#: to outlive the certificates themselves — "no record" and "never issued" would
#: otherwise be the same answer.
