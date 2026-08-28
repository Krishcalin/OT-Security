"""
OT Sensor Fleet — the analysis server (OTS-SRS-001, Phase 3+).

Receives observations from collectors, keeps what was and was not seen, and
serves the estate view.

The organising rule is the same one the collector is built around, carried
across the wire: the server must always be able to distinguish "we looked and
saw nothing" from "we did not look". A collector reports degraded and
unmeasurable windows and announces delivery gaps; this side stores them as
first-class records and computes coverage from what actually arrived. Accepting
that honesty and then rendering a continuous timeline would discard it at the
last step.
"""
from . import api, ingest, schema, store
from .ingest import (AssetState, CoverageSummary, Decision, Verdict,
                     asset_state, decide, summarise_coverage, validate)
from .schema import DDL, RETENTION_MONTHS, SCHEMA_VERSION
from .store import Store, StoreError

__all__ = [
    "api", "ingest", "schema", "store",
    "AssetState", "CoverageSummary", "Decision", "Verdict",
    "asset_state", "decide", "summarise_coverage", "validate",
    "DDL", "RETENTION_MONTHS", "SCHEMA_VERSION",
    "Store", "StoreError",
]
