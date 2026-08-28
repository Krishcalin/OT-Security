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
from . import (analysis, api, authn, authn_api, ca, containment,
               enrolment, estate, health, ingest, packs, qr, schema,
               severity, store, totp, vulnmatch, zones)
from .ingest import (AssetState, CoverageSummary, Decision, Verdict,
                     asset_state, decide, summarise_coverage, validate)
from .authn import (AuthError, PasswordPolicyError, decide_login,
                    hash_password, verify_password)
from .ca import CaError, CertificateAuthority, IssuedCertificate
from .packs import ContentSigner, PackError, SignedPack, fleet_drift
from .enrolment import (EnrolmentError, MintedToken, decide_issue,
                        decide_renewal, hash_token, mint)
from .schema import DDL, RETENTION_MONTHS, SCHEMA_VERSION
from .estate import (EstateAsset, EstateCoverage, estate_coverage, merge,
                     orphaned_detections, reattach_detections)
from .store import Store, StoreError
from .vulnmatch import (AssetMatch, Corpus, MatchState, Priority,
                        load_corpus, match_estate, reprioritise)
from .zones import (SiteTopology, ZoneBasis, ZoneConfidence,
                    derive as derive_zones, overall_confidence)

__all__ = [
    "api", "authn", "authn_api", "ca", "containment", "enrolment",
    "health", "ingest", "packs", "qr", "schema", "severity", "store",
    "totp",
    "ContentSigner", "PackError", "SignedPack", "fleet_drift",
    "AuthError", "PasswordPolicyError", "decide_login", "hash_password",
    "verify_password",
    "CaError", "CertificateAuthority", "IssuedCertificate",
    "EnrolmentError", "MintedToken", "decide_issue", "decide_renewal",
    "hash_token", "mint",
    "AssetState", "CoverageSummary", "Decision", "Verdict",
    "asset_state", "decide", "summarise_coverage", "validate",
    "DDL", "RETENTION_MONTHS", "SCHEMA_VERSION",
    "Store", "StoreError",
    "estate", "vulnmatch",
    "EstateAsset", "EstateCoverage", "estate_coverage", "merge",
    "orphaned_detections", "reattach_detections",
    "AssetMatch", "Corpus", "MatchState", "Priority",
    "load_corpus", "match_estate", "reprioritise",
    "analysis", "zones",
    "SiteTopology", "ZoneBasis", "ZoneConfidence", "derive_zones",
    "overall_confidence",
]
