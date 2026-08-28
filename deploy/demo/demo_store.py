"""
An in-memory estate, for looking at the console.

WHAT THIS IS NOT
────────────────
It is not the product's storage. `ot_server/store.py` is PostgreSQL and is what
a deployment runs; this is a dictionary that answers the same method names so
the screens have something to draw. It exists so somebody can see the console
without provisioning a database, enrolling a collector and waiting for a capture
window.

Everything it holds is invented. The site names, the vendors, the one collector
that is dropping frames — all fabricated, and deliberately fabricated to be
UNTIDY, because a demo estate where everything is clean shows none of the
behaviour this console was built for. The interesting screens are the ones with
a hole in them.

So the seed includes, on purpose:

  * two substations that both use 10.0.0.x, which is the merge trap `estate.py`
    exists to avoid — the inventory must show two devices, not one;
  * a collector whose windows are DEGRADED, so estate coverage is not clean and
    every count on the estate screen carries a qualified badge;
  * an asset that stopped being observed, so the change screen has a row;
  * a revoked certificate, so the fleet screen shows one;
  * no CVE corpus, so "0 actionable" renders as NOT MEASURED rather than as a
    clean estate. That is the single most representative thing on the screen.
"""
from __future__ import annotations

import datetime
import hashlib
from typing import Dict, List, Optional


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _asset(collector: str, key: str, window: str = "w-42", **attributes) -> Dict:
    return {
        "collector_id": collector,
        "asset_key": key,
        "first_seen": 1_760_000_000.0,
        "last_seen": 1_760_600_000.0,
        "observation_count": 1420,
        "last_observed_window": window,
        "last_coverage": attributes.pop("coverage", "complete"),
        "attributes": attributes,
    }


class DemoStore:
    """Every method `ot_server/api.py` calls, answered from memory."""

    def __init__(self) -> None:
        self.operators: Dict[str, Dict] = {}
        self.sessions: Dict[str, Dict] = {}
        self.totp: Dict[str, Dict] = {}
        self.recovery: Dict[str, Dict] = {}
        self.certs: Dict[str, Dict] = {}
        self.tokens: Dict[str, Dict] = {}
        self.sites = {
            "pi-alderley-01": "Alderley Substation",
            "pi-alderley-02": "Alderley Substation",
            "pi-marchwood-01": "Marchwood Substation",
        }
        self._assets = _seed_assets()
        self._flows = _seed_flows()
        self._detections = _seed_detections()
        self._packs: Dict[Any, Dict] = {}

    # ── the estate ────────────────────────────────────────────────────────

    def collector_ids(self) -> List[str]:
        return sorted(self.sites)

    def collector_sites(self) -> Dict[str, str]:
        return dict(self.sites)

    def all_assets(self, limit: int = 5000) -> List[Dict]:
        return [dict(a) for a in self._assets]

    def assets(self, collector_id: Optional[str] = None,
               limit: int = 500) -> List[Dict]:
        return [dict(a) for a in self._assets
                if collector_id in (None, a["collector_id"])]

    def all_flows(self, limit: int = 20000) -> List[Dict]:
        return [dict(f) for f in self._flows]

    def all_detections(self, limit: int = 20000) -> List[Dict]:
        return [dict(d) for d in self._detections]

    def recent_windows(self, collector_id: str) -> List[Dict]:
        # Marchwood is dropping frames. Everything the estate screen says about
        # totals is therefore a floor, and it says so.
        if collector_id == "pi-marchwood-01":
            return [{"coverage": "degraded"}] * 3 + [{"coverage": "complete"}] * 9
        return [{"coverage": "complete"}] * 12

    def recent_gaps(self, collector_id: str) -> List[Dict]:
        if collector_id == "pi-marchwood-01":
            return [{"records_lost": 218, "reason": "spool full during outage"}]
        return []

    def latest_window(self, collector_id: str) -> str:
        return "w-42"

    def ensure_collector(self, collector_id: str) -> None:
        self.sites.setdefault(collector_id, "")

    def set_site(self, collector_id: str, site: str) -> None:
        self.sites[collector_id] = site

    def record_heartbeat(self, payload: Dict) -> None:
        pass

    def collectors_health(self) -> List[Dict]:
        """All three reporting, one of them unhappy.

        Deliberately not a silent collector: silence makes the whole estate
        untrustworthy, which is correct and would bury every other screen under
        one alarm. The demo shows a collector that is up and struggling, which
        is the commoner and more interesting state.
        """
        now = _now()
        return [
            {"collector_id": "pi-alderley-01", "site": "Alderley Substation",
             "last_heartbeat": now, "capture_state": "complete",
             "queue_depth": 0, "enabled": True, "rulepack_version": "1",
             "collector_version": "0.1.0"},
            {"collector_id": "pi-alderley-02", "site": "Alderley Substation",
             "last_heartbeat": now, "capture_state": "complete",
             "queue_depth": 12, "enabled": True, "rulepack_version": "1",
             "collector_version": "0.1.0"},
            {"collector_id": "pi-marchwood-01", "site": "Marchwood Substation",
             "last_heartbeat": now, "capture_state": "degraded",
             "queue_depth": 780, "enabled": True, "rulepack_version": "1",
             "collector_version": "0.1.0"},
        ]

    def latest_pack_version(self, kind: str) -> int:
        return max([r["version"] for r in self._packs.values()
                    if r["kind"] == kind] or [0])

    def reported_pack_versions(self) -> Dict[str, Any]:
        """One current, one a version behind, one that has never said.

        The three states the fleet view has to keep apart — and the middle one
        is the whole reason it exists: a collector that refused or missed a pack
        keeps running and goes quiet about everything the newer pack would have
        found.
        """
        return {"pi-alderley-01": 2, "pi-alderley-02": 1,
                "pi-marchwood-01": None}

    def publish_pack(self, pack, published_by: str = "") -> None:
        self._packs[(pack.kind, pack.version)] = {
            "kind": pack.kind, "version": pack.version,
            "created_at": pack.created_at, "digest": pack.digest,
            "signature": pack.signature, "payload": pack.payload,
            "published_by": published_by}

    def latest_pack(self, kind: str) -> Optional[Dict]:
        rows = [r for r in self._packs.values() if r["kind"] == kind]
        if not rows:
            return None
        return dict(max(rows, key=lambda r: r["version"]))

    def packs(self, kind=None) -> List[Dict]:
        return [dict(r) for r in sorted(self._packs.values(),
                                        key=lambda r: -r["version"])
                if kind in (None, r["kind"])]

    # ── certificates ──────────────────────────────────────────────────────

    def certificates(self, collector_id: Optional[str] = None) -> List[Dict]:
        return [dict(c) for c in self.certs.values()
                if collector_id in (None, c["collector_id"])]

    def active_certificates(self, collector_id: str) -> List[Dict]:
        now = _now()
        return [dict(c) for c in self.certs.values()
                if c["collector_id"] == collector_id
                and c["revoked_at"] is None and c["not_after"] > now]

    def certificate_by_fingerprint(self, fingerprint: str) -> Optional[Dict]:
        for row in self.certs.values():
            if row["fingerprint"] == fingerprint:
                return dict(row)
        return None

    def record_certificate(self, issued) -> None:
        self.certs[issued.serial] = {
            "serial": issued.serial, "collector_id": issued.collector_id,
            "subject": issued.subject, "fingerprint": issued.fingerprint,
            "not_before": issued.not_before, "not_after": issued.not_after,
            "revoked_at": None, "revocation_reason": ""}

    def revoke_certificate(self, serial: str, reason: str) -> bool:
        row = self.certs.get(serial)
        if row is None or row["revoked_at"] is not None:
            return False
        row["revoked_at"] = _now()
        row["revocation_reason"] = reason
        return True

    # ── enrolment tokens ──────────────────────────────────────────────────

    def create_enrolment_token(self, minted) -> None:
        self.tokens[minted.token_hash] = {
            "collector_id": minted.collector_id, "site": minted.site,
            "expires_at": minted.expires_at, "used_at": None,
            "allow_reissue": minted.allow_reissue, "used_serial": ""}

    def redeem_enrolment_token(self, token_hash: str) -> Optional[Dict]:
        row = self.tokens.get(token_hash)
        if row is None or row["used_at"] is not None:
            return None
        if row["expires_at"] <= _now():
            return None
        row["used_at"] = _now()
        return {"collector_id": row["collector_id"], "site": row["site"],
                "allow_reissue": row["allow_reissue"]}

    def release_enrolment_token(self, token_hash: str) -> bool:
        row = self.tokens.get(token_hash)
        if row is None or row["used_serial"]:
            return False
        row["used_at"] = None
        return True

    def record_token_serial(self, token_hash: str, serial: str) -> None:
        self.tokens[token_hash]["used_serial"] = serial

    # ── operators ─────────────────────────────────────────────────────────

    def operator_count(self) -> int:
        return len(self.operators)

    def create_operator(self, username: str, password_hash: str,
                        display_name: str = "") -> None:
        self.operators[username] = {
            "username": username, "display_name": display_name or username,
            "password_hash": password_hash, "status": "active",
            "last_login_at": None}

    def operator(self, username: str) -> Optional[Dict]:
        row = self.operators.get((username or "").strip().lower())
        return dict(row) if row else None

    def set_operator_password(self, username: str, password_hash: str) -> None:
        self.operators[username]["password_hash"] = password_hash

    def note_operator_login(self, username: str) -> None:
        self.operators[username]["last_login_at"] = _now()

    # ── sessions ──────────────────────────────────────────────────────────

    def open_session(self, token_hash: str, username: str, window) -> None:
        def stamp(value):
            return datetime.datetime.fromtimestamp(
                value, datetime.timezone.utc)

        self.sessions[token_hash] = {
            "token_hash": token_hash, "username": username,
            "issued_at": stamp(window.issued_at),
            "expires_at": stamp(window.expires_at),
            "absolute_deadline": stamp(window.absolute_deadline)}

    def session(self, token_hash: str) -> Optional[Dict]:
        row = self.sessions.get(token_hash)
        if row is None:
            return None
        now = _now()
        if row["expires_at"] <= now or row["absolute_deadline"] <= now:
            return None
        operator = self.operators[row["username"]]
        out = dict(row)
        out["status"] = operator["status"]
        out["display_name"] = operator["display_name"]
        return out

    def touch_session(self, token_hash: str, expires_at) -> None:
        row = self.sessions.get(token_hash)
        if row is not None:
            row["expires_at"] = min(expires_at, row["absolute_deadline"])

    def close_session(self, token_hash: str) -> None:
        self.sessions.pop(token_hash, None)

    def close_all_sessions(self, username: str) -> int:
        doomed = [k for k, v in self.sessions.items()
                  if v["username"] == username]
        for key in doomed:
            del self.sessions[key]
        return len(doomed)

    # ── second factor ─────────────────────────────────────────────────────

    def totp_state(self, username: str) -> Optional[Dict]:
        row = self.totp.get(username)
        return dict(row) if row else None

    def stage_totp_secret(self, username: str, secret: str) -> None:
        self.totp[username] = {"username": username, "secret": secret,
                               "enabled": False, "last_counter": -1,
                               "enrolled_at": None}

    def enable_totp(self, username: str, counter: int) -> None:
        self.totp[username].update(enabled=True, last_counter=counter,
                                   enrolled_at=_now())

    def disable_totp(self, username: str) -> None:
        self.totp.pop(username, None)
        self.recovery.pop(username, None)

    def record_totp_counter(self, username: str, counter: int) -> None:
        row = self.totp[username]
        row["last_counter"] = max(row["last_counter"], counter)

    def store_recovery_codes(self, username: str,
                             fingerprints: List[str]) -> None:
        self.recovery[username] = {f: None for f in fingerprints}

    def unused_recovery_fingerprints(self, username: str) -> List[str]:
        return [f for f, used in (self.recovery.get(username) or {}).items()
                if used is None]

    def spend_recovery_code(self, username: str, fingerprint: str) -> bool:
        codes = self.recovery.get(username) or {}
        if codes.get(fingerprint, "spent") is not None:
            return False
        codes[fingerprint] = _now()
        return True

    # ── ingest, unused by the console but part of the surface ─────────────

    def has_batch(self, batch_id: str) -> bool:
        return False

    def write_batch(self, decision, window=None) -> None:
        pass

    def write_gap(self, collector_id: str, gap: Dict) -> None:
        pass


def _seed_assets() -> List[Dict]:
    """Two substations, addressed the way a substation actually is.

    Purdue levels are separated by subnet, because that is how zones get
    derived and because a flat estate has no direction in it — every
    conversation reads `lateral` and the communications screen has nothing to
    say:

        10.0.1.x   Level 1, basic control: PLCs and RTUs
        10.0.2.x   Level 2, supervisory: HMIs
        10.0.3.x   Level 3, site operations: engineering workstations

    And both sites still use 10.0.1.11. That overlap is the point:
    `estate.merge` scopes IP identity to a site, so the same address at
    Alderley and at Marchwood must appear as TWO devices. A demo estate
    without it would not show the behaviour the merge exists for.
    """
    return [
        _asset("pi-alderley-01", "ip:10.0.1.11", ip="10.0.1.11",
               mac="00:1b:1b:0a:11:01", vendor="Siemens", model="S7-1500",
               firmware="V4.2", role="plc", protocol="s7comm"),
        _asset("pi-alderley-01", "ip:10.0.1.12", ip="10.0.1.12",
               mac="00:1b:1b:0a:11:02", vendor="Siemens", model="S7-1200",
               role="plc", protocol="s7comm"),
        _asset("pi-alderley-01", "ip:10.0.1.30", ip="10.0.1.30",
               mac="00:0f:8f:0a:30:01", vendor="ABB", model="RTU560",
               role="rtu", protocol="iec104"),
        _asset("pi-alderley-02", "ip:10.0.1.11", ip="10.0.1.11",
               mac="00:1b:1b:0a:11:01", vendor="Siemens", role="plc",
               protocol="s7comm"),
        _asset("pi-alderley-02", "ip:10.0.2.60", ip="10.0.2.60",
               mac="9c:b6:54:0a:60:01", vendor="Advantech", role="hmi",
               protocol="modbus"),
        # Quiet since the previous window: the change screen's row.
        _asset("pi-alderley-02", "ip:10.0.2.61", ip="10.0.2.61",
               window="w-38", mac="9c:b6:54:0a:61:01", vendor="Advantech",
               role="hmi", protocol="modbus"),
        # The same address at another plant. Two devices, not one.
        # The model string is what the DEVICE announces, not a human
        # shorthand: the CVE corpus matches on product patterns, and
        # "Modicon M580" matches five advisories where "M580" matches none.
        # Getting that wrong in seed data hid the withheld-correction path.
        _asset("pi-marchwood-01", "ip:10.0.1.11", ip="10.0.1.11",
               mac="00:80:f4:0b:11:01", vendor="Schneider",
               model="Modicon M580", firmware="2.7", role="plc",
               protocol="modbus", coverage="degraded"),
        _asset("pi-marchwood-01", "ip:10.0.1.40", ip="10.0.1.40",
               mac="00:80:f4:0b:40:01", vendor="Schneider", role="rtu",
               protocol="dnp3", coverage="degraded"),
        _asset("pi-marchwood-01", "ip:10.0.3.90", ip="10.0.3.90",
               mac="00:50:56:0b:90:01", vendor="VMware", role="engineering",
               protocol="rdp", coverage="degraded"),

        # ── the three identification outcomes ─────────────────────────────
        #
        # The point of the assets screen is that these look DIFFERENT from
        # each other. A demo showing only devices that identified cleanly
        # would hide the case the design exists for.

        # 1. A ring switch, named by its own LLDP advertisement. Nothing else
        #    on the network can see this box: it speaks no industrial
        #    protocol, and its management traffic never crosses the mirror.
        #    The management address in the advertisement is why it has an IP
        #    here at all.
        _asset("pi-marchwood-01", "ip:10.0.0.2", ip="10.0.0.2",
               mac="00:80:63:0b:00:02", vendor="Hirschmann", make="Hirschmann",
               model="RSP20", os_name="HiOS", os_version="08.5.02",
               firmware="08.5.02", hostname="MARCHWOOD-RING-SW01",
               asset_identifier="00:80:63:0B:00:02",
               identified_by="lldp-system-description",
               device_type="Switch", role="switch", protocol="lldp",
               coverage="degraded"),

        # 2. A switch that advertised, and whose description matches no
        #    pattern this build carries. PRESENT in the estate, with no
        #    invented version: the device is real, the version would not have
        #    been, and it is about to be matched against a CVE corpus.
        _asset("pi-marchwood-01", "ip:10.0.0.3", ip="10.0.0.3",
               mac="00:80:63:0b:00:03", hostname="MARCHWOOD-RING-SW02",
               asset_identifier="00:80:63:0B:00:03",
               identified_by="lldp-advertisement",
               device_type="Switch", role="switch", protocol="lldp",
               coverage="degraded"),

        # 3. An FRTU on a ring main unit speaking only IEC 60870-5-104.
        #    That protocol has NO identification service, so no amount of
        #    watching will ever produce a model or a firmware version. The
        #    vendor comes from the OUI and the asset identifier is the common
        #    address of ASDU -- which is what the device is called on the
        #    SCADA mimic, and is not its IP.
        #
        #    This row is the one worth looking at: its empty cells are a limit
        #    of what is knowable passively, not a gap in the scan.
        _asset("pi-marchwood-01", "ip:10.0.4.21", ip="10.0.4.21",
               mac="00:0f:8f:0b:21:01", vendor="ABB",
               asset_identifier="CASDU 4021", role="frtu",
               protocol="iec104", coverage="degraded"),

        # 4. A 61850 IED that answered MMS Identify -- the richest
        #    identification a passive listener ever gets from a relay.
        _asset("pi-marchwood-01", "ip:10.0.1.55", ip="10.0.1.55",
               mac="00:1b:1b:0b:55:01", vendor="SIEMENS", make="SIEMENS",
               model="SIPROTEC 5 7SJ85", firmware="V08.30",
               os_version="V08.30", asset_identifier="MARCHWOOD_P1_CTRL",
               identified_by="mms-identify", device_type="IED", role="ied",
               protocol="iec61850-mms", coverage="degraded"),
    ]


def _seed_flows() -> List[Dict]:
    """Enough conversation for the topology engine to derive zones from."""
    def flow(collector, src, dst, protocol, port, packets=4200):
        key = hashlib.sha256(
            ("%s%s%s%d" % (collector, src, dst, port)).encode()).hexdigest()[:16]
        return {"flow_key": key, "collector_id": collector,
                "first_seen": 1_760_000_000.0, "last_seen": 1_760_600_000.0,
                "observation_count": packets,
                "attributes": {"src_ip": src, "dst_ip": dst,
                               "protocol": protocol, "dst_port": str(port),
                               "packet_count": packets,
                               "byte_count": packets * 74}}

    return [
        flow("pi-alderley-01", "10.0.2.60", "10.0.1.11", "s7comm", 102),
        flow("pi-alderley-01", "10.0.2.60", "10.0.1.12", "s7comm", 102),
        flow("pi-alderley-01", "10.0.1.30", "10.0.1.11", "iec104", 2404),
        flow("pi-alderley-02", "10.0.2.60", "10.0.1.30", "iec104", 2404),
        # An engineering workstation at Level 3 reaching a controller at
        # Level 1 directly. This is the conversation segmentation exists to
        # prevent, and the one the communications screen is built to surface.
        flow("pi-marchwood-01", "10.0.3.90", "10.0.1.11", "modbus", 502),
        flow("pi-marchwood-01", "10.0.1.40", "10.0.1.11", "dnp3", 20000),
        # An engineering workstation reaching a controller directly.
        flow("pi-marchwood-01", "10.0.3.90", "10.0.1.40", "rdp", 3389, 980),
    ]


def _seed_detections() -> List[Dict]:
    return [
        {"detection_key": "det-1", "collector_id": "pi-marchwood-01",
         "asset_key": "ip:10.0.3.90", "rule_id": "cleartext-rdp",
         "severity": "high", "last_coverage": "degraded",
         "rulepack_version": "demo",
         "attributes": {"rule_id": "cleartext-rdp",
                        "title": "Remote desktop into the control network",
                        "severity": "high", "category": "access",
                        "description": "An engineering workstation reached a "
                                       "controller over RDP.",
                        "remediation": "Terminate remote access at a jump host "
                                       "in the DMZ."}},
        {"detection_key": "det-2", "collector_id": "pi-alderley-01",
         "asset_key": "ip:10.0.1.12", "rule_id": "s7-stop-observed",
         "severity": "medium", "last_coverage": "complete",
         "rulepack_version": "demo",
         "attributes": {"rule_id": "s7-stop-observed",
                        "title": "PLC stop command observed",
                        "severity": "medium", "category": "process",
                        "description": "An S7 stop was seen on the wire.",
                        "remediation": "Confirm it was a planned maintenance "
                                       "action."}},
        # A detection whose asset row never arrived. The findings screen calls
        # this out rather than dropping it — see estate.reattach_detections.
        {"detection_key": "det-3", "collector_id": "pi-marchwood-01",
         "asset_key": "ip:10.0.1.199", "rule_id": "unknown-device",
         "severity": "low", "last_coverage": "degraded",
         "rulepack_version": "demo", "attributes": {}},
    ]
