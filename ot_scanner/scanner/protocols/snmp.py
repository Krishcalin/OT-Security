"""
SNMP — the OS version for everything that answers the NMS.

WHY THIS MATTERS ON A DISTRIBUTION NETWORK
──────────────────────────────────────────
IEC 60870-5-104 has no device-identification service. None. An FRTU on a ring
main unit that speaks only 104 will never tell a passive listener its model or
its firmware, no matter how long the collector watches — that is the protocol,
not the tool.

What such a device very often DOES answer is SNMP, because the utility's NMS
polls it for availability. Those replies cross the mirror, and `sysDescr` is the
one field in this whole system that reliably carries an OS version for a device
with no identification service of its own.

THE PATTERN TABLE IS NOT DUPLICATED HERE
────────────────────────────────────────
LLDP's System Description TLV is *defined* as the `sysDescr` MIB object
(802.1AB 8.5.8). It is the same string from the same source, so the same
`lldp.identify()` reads it, and a switch identified over LLDP and the same
switch identified over SNMP cannot disagree about what it is. Two tables would
have drifted within a release.

THE COMMUNITY STRING IS A CREDENTIAL, IN CLEARTEXT
──────────────────────────────────────────────────
SNMP v1 and v2c authenticate with a community string sent in the clear, so a
passive collector reads it off the wire exactly as an attacker on the same
mirror would. That is worth reporting as a finding in its own right, and a
DEFAULT community ("public", "private") on a substation network is worth more
than a finding — it is read-only access to the plant's topology for anyone with
a port.

This module records that the string was observed and whether it is a default. It
does NOT record the string itself: writing a live credential into an
observation batch, a database with 13-month retention and an HTML report would
be creating the exposure this is meant to report.

SNMPv3 IS NOT PARSED, AND SAYS SO
─────────────────────────────────
v3 authenticates and may encrypt. Its payload is deliberately unreadable here,
which is the correct outcome and not a gap to be worked around — but a device
seen speaking v3 is recorded as SEEN, so it is never mistaken for a device that
was never observed. "Encrypted, therefore unidentified" and "absent" must not
look the same.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .base import AnalysisResult, BaseProtocolAnalyzer
from .ber import (TAG_INTEGER, TAG_NULL, TAG_OCTET_STRING, TAG_OID,
                  TAG_SEQUENCE, read_integer, read_oid, read_string, read_tlv)
from .lldp import identify as identify_description

SNMP_PORT = 161
SNMP_TRAP_PORT = 162

#: SNMP PDU tags (context-specific, constructed).
PDU_GET_REQUEST = 0xA0
PDU_GET_NEXT = 0xA1
PDU_GET_RESPONSE = 0xA2
PDU_SET_REQUEST = 0xA3
PDU_TRAP_V1 = 0xA4
PDU_GET_BULK = 0xA5
PDU_INFORM = 0xA6
PDU_TRAP_V2 = 0xA7

PDU_NAMES = {
    PDU_GET_REQUEST: "get-request", PDU_GET_NEXT: "get-next-request",
    PDU_GET_RESPONSE: "get-response", PDU_SET_REQUEST: "set-request",
    PDU_TRAP_V1: "trap-v1", PDU_GET_BULK: "get-bulk-request",
    PDU_INFORM: "inform-request", PDU_TRAP_V2: "trap-v2",
}

VERSIONS = {0: "v1", 1: "v2c", 3: "v3"}

#: The System group (RFC 1213). These four are the whole of what identifies a
#: device; the rest of the MIB tree is operational data this does not collect.
SYSTEM_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.2.0": "sysObjectID",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
}

#: A community string every scanning tool on earth tries first.
DEFAULT_COMMUNITIES = frozenset((
    "public", "private", "manager", "admin", "cisco", "community",
    "read", "write", "monitor", "snmp",
))

#: IANA enterprise numbers, for vendors that appear on utility networks. Only
#: numbers verifiable from the vendor's own MIB registration are listed; an
#: unlisted enterprise is REPORTED AS ITS NUMBER rather than guessed at, so an
#: operator can look it up instead of reading an invented vendor name.
ENTERPRISES = {
    9: "Cisco",
    248: "Hirschmann",
    3833: "Schneider Electric",
    4196: "Siemens",
    8691: "Moxa",
    15004: "RuggedCom",
}


def _value(tag: int, raw: bytes):
    if tag == TAG_OCTET_STRING:
        return read_string(raw)
    if tag == TAG_OID:
        return read_oid(raw)
    if tag == TAG_INTEGER:
        return read_integer(raw)
    if tag == TAG_NULL:
        return None
    return raw.hex()


def vendor_from_sysobjectid(oid: str) -> Dict[str, str]:
    """The enterprise number inside sysObjectID names the vendor.

    `1.3.6.1.4.1.<enterprise>.…`. An enterprise absent from the table is
    reported as its number, never as a guessed name.
    """
    prefix = "1.3.6.1.4.1."
    if not oid or not oid.startswith(prefix):
        return {}
    rest = oid[len(prefix):].split(".")
    if not rest or not rest[0].isdigit():
        return {}
    number = int(rest[0])
    name = ENTERPRISES.get(number)
    if name:
        return {"vendor": name, "make": name,
                "identified_by": "snmp-sysobjectid"}
    return {"vendor_enterprise": number,
            "identification": "IANA enterprise %d is not in the table; look it "
                              "up rather than assuming a vendor" % number}


class SNMPAnalyzer(BaseProtocolAnalyzer):
    """Reads device identification out of SNMP responses and traps."""

    def __init__(self):
        self._devices: Dict[str, Dict] = {}

    def can_analyze(self, sport: int, dport: int, proto: str,
                    payload: bytes) -> bool:
        if proto.upper() != "UDP" or not payload:
            return False
        if SNMP_PORT not in (sport, dport) and \
                SNMP_TRAP_PORT not in (sport, dport):
            return False
        return payload[0] == TAG_SEQUENCE

    def analyze(self, src_ip: str, dst_ip: str, sport: int, dport: int,
                proto: str, payload: bytes,
                timestamp: datetime) -> Optional[AnalysisResult]:
        if not self.can_analyze(sport, dport, proto, payload):
            return None
        message = self.parse(payload)
        if not message:
            return None

        # A response or a trap comes FROM the device; a request goes TO it.
        # Identification only ever belongs to the device that spoke about
        # itself, so a request contributes presence and nothing more.
        pdu = message.get("pdu_type", "")
        device_ip = src_ip if pdu in ("get-response", "trap-v1", "trap-v2") \
            else dst_ip

        record = self._devices.setdefault(device_ip, {})
        record.update({k: v for k, v in message.items() if k != "varbinds"})
        for name, value in (message.get("varbinds") or {}).items():
            record[name] = value

        # `message` carries its own "protocol" key, which would collide with
        # the parameter of the same name. The reserved names are stripped
        # rather than the key renamed: the dict is also what lands on the
        # device record, where "protocol" is the natural spelling.
        details = {k: v for k, v in message.items()
                   if k not in ("protocol", "port", "confidence", "transport")}
        detection = self._make_detection(
            protocol="SNMP", port=SNMP_PORT,
            confidence="high" if pdu == "get-response" else "medium",
            timestamp=timestamp, transport="UDP", **details)
        return [(device_ip, detection)]

    def get_sessions(self) -> Dict:
        return dict(self._devices)

    # ── the message ───────────────────────────────────────────────────────
    def parse(self, payload: bytes) -> Optional[Dict]:
        """One SNMP message into identification, or None. Never raises."""
        try:
            tag, body, _ = read_tlv(payload, 0)
            if tag != TAG_SEQUENCE:
                return None
            index = 0
            tag, raw, index = read_tlv(body, index)
            if tag != TAG_INTEGER:
                return None
            version = read_integer(raw)
            out: Dict = {"protocol": "SNMP",
                         "version": VERSIONS.get(version, "unknown(%d)" % version)}

            if version == 3:
                # Authenticated, possibly encrypted. Correct that it is
                # unreadable — but the device was SEEN, and that is recorded so
                # it is never confused with one that was never observed.
                out["pdu_type"] = "v3"
                out["identification"] = (
                    "SNMPv3 is authenticated and may be encrypted, so no "
                    "identification is available from it. The device was "
                    "observed; it was not identified.")
                return out

            tag, raw, index = read_tlv(body, index)
            if tag != TAG_OCTET_STRING:
                return None
            community = raw.decode("utf-8", "replace")
            # The string itself is NEVER recorded: it is a live credential and
            # this observation is written to a database with 13-month retention
            # and rendered into reports.
            out["community_observed"] = True
            out["community_is_default"] = community.lower() in DEFAULT_COMMUNITIES
            out["community_length"] = len(community)

            tag, pdu, index = read_tlv(body, index)
            out["pdu_type"] = PDU_NAMES.get(tag, "unknown(0x%02x)" % tag)
            varbinds = self._read_varbinds(tag, pdu)
            if varbinds:
                out["varbinds"] = varbinds
                out.update(self._identify(varbinds))
            return out
        except Exception:                                    # noqa: BLE001
            return None

    def _read_varbinds(self, pdu_tag: int, pdu: bytes) -> Dict[str, object]:
        """The System-group values out of a PDU's varbind list."""
        index = 0
        # v1 traps have a different header; everything else is
        # request-id / error-status / error-index then the varbinds.
        skip = 6 if pdu_tag == PDU_TRAP_V1 else 3
        for _ in range(skip):
            try:
                _tag, _raw, index = read_tlv(pdu, index)
            except ValueError:
                return {}
        try:
            tag, bindings, _ = read_tlv(pdu, index)
        except ValueError:
            return {}
        if tag != TAG_SEQUENCE:
            return {}

        found: Dict[str, object] = {}
        cursor = 0
        while cursor < len(bindings):
            try:
                tag, one, cursor = read_tlv(bindings, cursor)
            except ValueError:
                break
            if tag != TAG_SEQUENCE:
                continue
            try:
                tag, raw_oid, inner = read_tlv(one, 0)
                if tag != TAG_OID:
                    continue
                oid = read_oid(raw_oid)
                value_tag, raw_value, _ = read_tlv(one, inner)
            except ValueError:
                continue
            name = SYSTEM_OIDS.get(oid)
            if name:
                found[name] = _value(value_tag, raw_value)
        return found

    @staticmethod
    def _identify(varbinds: Dict[str, object]) -> Dict[str, object]:
        """Make, model and OS version from the System group.

        `sysDescr` is read by the SAME table LLDP uses, because it is the same
        MIB object arriving by a different road.
        """
        out: Dict[str, object] = {}
        description = varbinds.get("sysDescr")
        if isinstance(description, str) and description:
            identified = identify_description(description)
            if identified:
                out.update(identified)
                out["identified_by"] = "snmp-sysdescr"
            else:
                out["identification"] = "unrecognised sysDescr"
        object_id = varbinds.get("sysObjectID")
        if isinstance(object_id, str) and object_id:
            # Only fills what sysDescr could not: a parsed description is the
            # stronger evidence, since it carries a version as well as a vendor.
            for key, value in vendor_from_sysobjectid(object_id).items():
                out.setdefault(key, value)
        name = varbinds.get("sysName")
        if isinstance(name, str) and name:
            out["hostname"] = name
        return out
