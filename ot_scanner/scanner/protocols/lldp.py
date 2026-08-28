"""
LLDP (IEEE 802.1AB) — how the transport network names itself.

WHY THIS IS THE MOST VALUABLE PASSIVE SOURCE ON A SUBSTATION RING
─────────────────────────────────────────────────────────────────
The Ethernet switches carrying an MPLS-TP ring are the one class of device a
passive OT scanner otherwise cannot see. They do not speak IEC 104, they do not
answer Modbus, and their management traffic may never cross the mirror at all.
What they DO emit, unprompted, every 30 seconds, out of every port, is an LLDP
advertisement — and it contains more identification than any industrial protocol
carries:

    System Description  →  the OS and its version, in the vendor's own words
    Management Address  →  the IP an operator would use to reach it
    System Name         →  the hostname, usually the substation designation
    System Capabilities →  bridge / router, so a switch is typed as a switch
    Chassis ID          →  a stable identity across a management-IP change

That Management Address TLV is why switches can be inventoried BY IP at all,
which is what the deployment asks for. Without it a switch is a MAC on a ring
and nothing more.

WHAT THIS REFUSES TO DO
───────────────────────
A System Description is free text. Every vendor writes it differently and none
of them promise a format. This module carries a small table of patterns for the
switch families that actually appear on distribution rings, and when none of
them matches it records the description VERBATIM and leaves make, model and
firmware empty.

That is deliberate and it is the whole design. A regex loose enough to pull a
version out of any string will pull the wrong version out of most of them, and a
wrong firmware version is worse than none: it is matched against a CVE corpus,
and it produces either a vulnerability the device does not have or — far worse —
silence about one it does. The raw description is kept on the device either way,
so an operator can always read what the switch actually said.

LLDP IS ALSO UNAUTHENTICATED
────────────────────────────
Anything on the segment can emit it and claim to be anything. It is trusted here
for INVENTORY, never for a security decision, and the confidence recorded on the
detection says so. A device known only from LLDP is a device that told us about
itself.
"""
from __future__ import annotations

import re
import socket
import struct
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .base import BaseL2Analyzer

ETH_LLDP = 0x88CC

#: The three reserved multicast destinations LLDP is sent to (802.1AB 8.1).
LLDP_MULTICAST = frozenset((
    "01:80:C2:00:00:0E",      # nearest bridge
    "01:80:C2:00:00:03",      # nearest non-TPMR bridge
    "01:80:C2:00:00:00",      # nearest customer bridge
))

# ── TLV types (802.1AB table 8-1) ──────────────────────────────────────────
TLV_END = 0
TLV_CHASSIS_ID = 1
TLV_PORT_ID = 2
TLV_TTL = 3
TLV_PORT_DESC = 4
TLV_SYSTEM_NAME = 5
TLV_SYSTEM_DESC = 6
TLV_CAPABILITIES = 7
TLV_MANAGEMENT_ADDR = 8
TLV_ORG_SPECIFIC = 127

# Chassis ID and Port ID have DIFFERENT subtype registries (802.1AB 8.5.2 and
# 8.5.3), and they are easy to conflate because they look alike. Subtype 5 is a
# network address on a chassis and an INTERFACE NAME on a port. Sharing one
# table hex-encoded every Cisco port ID ("4769312f302f31" for "Gi1/0/1").
CHASSIS_MAC_SUBTYPE = 4
CHASSIS_NETWORK_SUBTYPE = 5
CHASSIS_TEXT_SUBTYPES = (1, 2, 3, 6, 7)

PORT_MAC_SUBTYPE = 3
PORT_NETWORK_SUBTYPE = 4
PORT_TEXT_SUBTYPES = (1, 2, 5, 6, 7)

#: System Capabilities bits (802.1AB table 8-4), low bit first.
CAPABILITIES = ("other", "repeater", "bridge", "wlan-ap", "router",
                "telephone", "docsis", "station")

#: A frame larger than this is not an LLDPDU.
MAX_LLDPDU = 1500


def _text(raw: bytes) -> str:
    """LLDP strings are not length-prefixed UTF-8 and are frequently padded."""
    return raw.split(b"\x00")[0].decode("utf-8", "replace").strip()


def _mac(raw: bytes) -> str:
    return ":".join("%02X" % b for b in raw)


# ── System Description → make, model, OS version ───────────────────────────
#
# Ordered. Each pattern was written against a real advertisement from the
# switch families that appear on distribution and substation rings. A family
# absent from this table is NOT guessed at.
#
# `os_name` is separate from `os_version` because the CVE corpus is keyed on the
# platform ("Cisco IOS", "HiOS", "ROS"), not on the marketing string.
DESCRIPTION_PATTERNS: Tuple[Tuple[str, str, re.Pattern], ...] = (
    # "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, ..."
    ("Cisco", "Cisco IOS", re.compile(
        r"Cisco IOS Software.*?,\s*(?P<model>\S+)\s+Software.*?Version\s+"
        r"(?P<version>[0-9][^\s,]*)", re.I | re.S)),
    # "Cisco IOS XE Software, Version 16.12.04"
    ("Cisco", "Cisco IOS XE", re.compile(
        r"Cisco IOS XE Software.*?Version\s+(?P<version>[0-9][^\s,]*)",
        re.I | re.S)),
    # Hirschmann (Belden) — the dominant ring switch in European/Indian OT.
    # "Hirschmann RSP20 ... SW: HiOS-2A-08.5.02"
    ("Hirschmann", "HiOS", re.compile(
        r"Hirschmann\s+(?P<model>[A-Z0-9\-]+).*?HiOS-\w+-(?P<version>\d[\d.]*)",
        re.I | re.S)),
    # Older Hirschmann Classic: "... SW: L3P-09.0.09"
    ("Hirschmann", "Hirschmann Classic", re.compile(
        r"Hirschmann\s+(?P<model>[A-Z0-9\-]+).*?SW:\s*\S*?-(?P<version>\d[\d.]*)",
        re.I | re.S)),
    # Siemens SCALANCE: "Siemens, SIMATIC NET, SCALANCE XM416-4C, ..., FW: V06.02.00"
    ("Siemens", "SCALANCE firmware", re.compile(
        r"SCALANCE\s+(?P<model>[A-Z0-9\-]+).*?FW:\s*V?(?P<version>[\d.]+)",
        re.I | re.S)),
    # RuggedCom (now Siemens), ubiquitous in utility substations.
    # "RuggedCom RSG2100 ... ROS v4.3.4"
    ("RuggedCom", "ROS", re.compile(
        r"RuggedCom\s+(?P<model>[A-Z0-9\-]+).*?ROS\s*v?(?P<version>[\d.]+)",
        re.I | re.S)),
    # Moxa: "Moxa EDS-408A ... V3.9 build 19010211"
    ("Moxa", "Moxa switch firmware", re.compile(
        r"Moxa\s+(?P<model>[A-Z]+-[A-Z0-9\-]+).*?V(?P<version>[\d.]+)",
        re.I | re.S)),
    # Westermo: "Westermo Lynx-3510 ... WeOS 4.32.3"
    ("Westermo", "WeOS", re.compile(
        r"Westermo\s+(?P<model>[A-Za-z0-9\-]+).*?WeOS\s+(?P<version>[\d.]+)",
        re.I | re.S)),
)


def identify(description: str) -> Dict[str, str]:
    """Make, model and OS version from a System Description, or empty fields.

    Empty rather than approximate. A wrong firmware version is matched against
    the CVE corpus and produces either a vulnerability the device does not have
    or silence about one it does.
    """
    text = (description or "").strip()
    if not text:
        return {}
    for make, os_name, pattern in DESCRIPTION_PATTERNS:
        found = pattern.search(text)
        if not found:
            continue
        fields = found.groupdict()
        out = {"make": make, "vendor": make, "os_name": os_name,
               "identified_by": "lldp-system-description"}
        if fields.get("model"):
            out["model"] = fields["model"]
        if fields.get("version"):
            out["os_version"] = fields["version"]
            out["firmware"] = fields["version"]
        return out
    return {}


class LLDPAnalyzer(BaseL2Analyzer):
    """Reads LLDP advertisements into device identification."""

    def __init__(self):
        #: chassis id -> the last advertisement seen from it.
        self._neighbours: Dict[str, Dict] = {}

    # ── the BaseL2Analyzer contract ───────────────────────────────────────
    def can_analyze_frame(self, eth_type: int, payload: bytes) -> bool:
        return eth_type == ETH_LLDP and bool(payload)

    def analyze_frame(self, src_mac: str, dst_mac: str, eth_type: int,
                      payload: bytes, timestamp: datetime) -> Optional[dict]:
        if not self.can_analyze_frame(eth_type, payload):
            return None
        advert = self.parse(payload)
        if not advert:
            return None
        advert["src_mac"] = src_mac
        advert["seen_at"] = timestamp.isoformat()
        # The chassis ID is stable across a management-IP change, so it is the
        # key. Falling back to the source MAC keeps an advertisement that omits
        # the chassis ID from overwriting a different neighbour's entry.
        self._neighbours[advert.get("chassis_id") or src_mac] = advert
        return advert

    def get_sessions(self) -> Dict:
        return dict(self._neighbours)

    # ── the LLDPDU ────────────────────────────────────────────────────────
    def parse(self, payload: bytes) -> Optional[Dict]:
        """One LLDPDU into a flat dict, or None if it is not one.

        Never raises. A malformed advertisement on a live ring must not stop
        capture, and a truncated TLV stops the walk rather than being guessed
        past.
        """
        if not payload or len(payload) > MAX_LLDPDU:
            return None
        out: Dict = {"protocol": "LLDP", "capabilities": [],
                     "management_addresses": []}
        offset = 0
        seen_tlvs = 0

        while offset + 2 <= len(payload):
            header = struct.unpack(">H", payload[offset:offset + 2])[0]
            tlv_type = header >> 9
            tlv_len = header & 0x01FF
            offset += 2
            if tlv_type == TLV_END:
                break
            if offset + tlv_len > len(payload):
                # Truncated. Keep what was already read rather than discarding
                # a usable advertisement, but stop walking.
                out["truncated"] = True
                break
            value = payload[offset:offset + tlv_len]
            offset += tlv_len
            seen_tlvs += 1
            self._read_tlv(tlv_type, value, out)

        # A valid LLDPDU opens with chassis, port and TTL. Requiring the
        # chassis ID keeps arbitrary 0x88CC traffic from becoming a device.
        if not seen_tlvs or "chassis_id" not in out:
            return None

        identified = identify(out.get("system_description", ""))
        out.update(identified)
        if out.get("system_description") and not identified:
            # Recorded so it is visible that the description was READ and not
            # recognised, rather than absent.
            out["identification"] = "unrecognised system description"
        return out

    def _read_tlv(self, tlv_type: int, value: bytes, out: Dict) -> None:
        try:
            if tlv_type == TLV_CHASSIS_ID and value:
                out["chassis_id_subtype"] = value[0]
                out["chassis_id"] = self._id_value(
                    value[0], value[1:], CHASSIS_MAC_SUBTYPE,
                    CHASSIS_NETWORK_SUBTYPE, CHASSIS_TEXT_SUBTYPES)
            elif tlv_type == TLV_PORT_ID and value:
                out["port_id"] = self._id_value(
                    value[0], value[1:], PORT_MAC_SUBTYPE,
                    PORT_NETWORK_SUBTYPE, PORT_TEXT_SUBTYPES)
            elif tlv_type == TLV_TTL and len(value) >= 2:
                out["ttl"] = struct.unpack(">H", value[:2])[0]
            elif tlv_type == TLV_PORT_DESC:
                out["port_description"] = _text(value)
            elif tlv_type == TLV_SYSTEM_NAME:
                out["system_name"] = _text(value)
            elif tlv_type == TLV_SYSTEM_DESC:
                out["system_description"] = _text(value)
            elif tlv_type == TLV_CAPABILITIES and len(value) >= 4:
                out["capabilities"] = self._capabilities(
                    struct.unpack(">H", value[2:4])[0])       # enabled, not able
                out["capabilities_supported"] = self._capabilities(
                    struct.unpack(">H", value[0:2])[0])
            elif tlv_type == TLV_MANAGEMENT_ADDR:
                address = self._management_address(value)
                if address:
                    out["management_addresses"].append(address)
                    out.setdefault("management_ip", address)
            elif tlv_type == TLV_ORG_SPECIFIC and len(value) >= 4:
                out.setdefault("org_specific", []).append(
                    "%02x%02x%02x/%d" % (value[0], value[1], value[2], value[3]))
        except Exception:                                    # noqa: BLE001
            # One unreadable TLV must not cost the whole advertisement. The
            # fields that did parse are still identification.
            out["tlv_errors"] = out.get("tlv_errors", 0) + 1

    @staticmethod
    def _id_value(subtype: int, raw: bytes, mac_subtype: int,
                  network_subtype: int, text_subtypes) -> str:
        """One ID TLV. The subtype registry is passed in because chassis and
        port do not share one — see the note beside the constants."""
        if subtype == mac_subtype and len(raw) == 6:
            return _mac(raw)
        if subtype == network_subtype and len(raw) >= 5 and raw[0] == 1:
            return socket.inet_ntoa(raw[1:5])
        if subtype in text_subtypes:
            return _text(raw)
        return raw.hex()

    @staticmethod
    def _capabilities(bits: int) -> List[str]:
        return [name for index, name in enumerate(CAPABILITIES)
                if bits & (1 << index)]

    @staticmethod
    def _management_address(value: bytes) -> Optional[str]:
        """Management Address TLV (802.1AB 8.5.9).

        Layout: length(1) subtype(1) address(length-1) ... — the length counts
        the subtype byte, which is the field most often got wrong.
        """
        if len(value) < 2:
            return None
        addr_len = value[0]
        if addr_len < 1 or 1 + addr_len > len(value):
            return None
        subtype = value[1]
        raw = value[2:1 + addr_len]
        if subtype == 1 and len(raw) == 4:                   # IANA IPv4
            return socket.inet_ntoa(raw)
        if subtype == 2 and len(raw) == 16:                  # IANA IPv6
            return socket.inet_ntop(socket.AF_INET6, raw)
        return None


def device_type_for(capabilities: List[str]) -> str:
    """What the advertisement says this box is.

    Bridge and router both appear on a substation ring switch that also does
    L3, so bridge is reported first: on this network it is a switch that
    happens to route, not a router that happens to bridge.
    """
    if "bridge" in capabilities:
        return "Switch"
    if "router" in capabilities:
        return "Router"
    if "wlan-ap" in capabilities:
        return "Wireless AP"
    if "station" in capabilities:
        return "Host"
    return "unknown"
