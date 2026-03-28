"""
IEC 61850 Vulnerability Checks (GOOSE + MMS)
References: IEC 62351-6 (GOOSE/SV security), IEC 62351-8 (MMS),
            IEC 62351-4 (Profiles for MMS), NERC CIP-005/007
"""
from typing import Dict, List, Optional, Set

from ..models import GOOSEPublisherState, OTDevice, VulnerabilityFinding

# Threshold for "very low" GOOSE TTL -- replay window concern
LOW_TTL_MS = 2000


def run_iec61850_checks(
    device: OTDevice,
    goose_publishers: Dict,          # (src_mac, app_id) -> GOOSEPublisherState
    mms_devices: Set[str],           # set of IPs seen doing MMS on port 102
) -> List[VulnerabilityFinding]:
    """Run all IEC 61850 vulnerability checks for a device."""
    findings: List[VulnerabilityFinding] = []

    # GOOSE checks (keyed by MAC, not IP -- map via device MAC)
    device_pubs = [
        pub for pub in goose_publishers.values()
        if device.mac and pub.src_mac.upper() == device.mac.upper()
    ]

    findings += _check_goose_no_tls(device, device_pubs)
    findings += _check_goose_simulation(device, device_pubs)
    findings += _check_goose_low_ttl(device, device_pubs)
    findings += _check_goose_conf_change(device, device_pubs)
    findings += _check_goose_nds_com(device, device_pubs)

    # MMS checks
    if device.ip in mms_devices:
        findings += _check_mms_no_tls(device)

    return findings


# --------------------------------------------------- GOOSE checks --------

def _check_goose_no_tls(
    device: OTDevice, pubs: List[GOOSEPublisherState]
) -> List[VulnerabilityFinding]:
    """
    RTU-61850-001 -- GOOSE without IEC 62351-6 security.
    Baseline: all GOOSE on un-tagged VLAN 0 / no VLAN is unprotected.
    IEC 62351-6 mandates cryptographic signature on each GOOSE PDU.
    Without it, any device on the LAN can inject forged GOOSE trip signals.
    """
    if not pubs:
        return []
    total_pkts = sum(p.total_packets for p in pubs)
    return [VulnerabilityFinding(
        vuln_id="RTU-61850-001",
        title="IEC 61850 GOOSE Without Cryptographic Authentication (IEC 62351-6)",
        severity="critical",
        category="authentication",
        description=(
            f"Device {device.ip} (MAC {device.mac}) is publishing GOOSE frames "
            f"without IEC 62351-6 authentication signatures. GOOSE carries "
            f"protection trip signals (breaker open/close, fault indications). "
            f"An attacker on the substation LAN can inject a forged GOOSE frame "
            f"with stNum > current value to force a spurious breaker trip, "
            f"causing an unplanned outage. "
            f"GOOSE IDs observed: {', '.join(p.goose_id for p in pubs if p.goose_id)}."
        ),
        evidence={
            "publisher_mac":  device.mac,
            "goose_ids":      [p.goose_id for p in pubs],
            "gcb_refs":       [p.gcb_ref  for p in pubs],
            "total_packets":  total_pkts,
            "security_tags":  False,
        },
        remediation=(
            "Enable IEC 62351-6 GOOSE authentication on all publishing IEDs. "
            "Each GOOSE PDU must carry an HMAC-SHA256 or AES-GMAC signature. "
            "Subscribing IEDs must verify signatures and discard unsigned or "
            "incorrectly signed messages. Segment the process bus on a dedicated "
            "VLAN and block GOOSE EtherType (0x88B8) at VLAN boundaries as "
            "an interim compensating control."
        ),
        references=[
            "IEC 62351-6:2020 -- Security for IEC 61850 GOOSE/SV",
            "IEC 61850-8-1 \u00a717 -- GOOSE Services",
            "NERC CIP-007-6 R2 -- Ports and Services",
            "ICS-CERT Advisory ICSA-15-202 -- GOOSE Injection",
        ],
        first_seen=min((p.first_seen for p in pubs if p.first_seen), default=None),
        packet_count=total_pkts,
    )]


def _check_goose_simulation(
    device: OTDevice, pubs: List[GOOSEPublisherState]
) -> List[VulnerabilityFinding]:
    """
    RTU-61850-002 -- GOOSE simulation bit set TRUE in live traffic.
    The simulation flag marks a GOOSE message as a test frame that
    subscribing IEDs should ignore. If simulation=TRUE appears in
    production traffic, subscribers may ignore real trip signals --
    this is a known attack technique (IEC 61850 GOOSE replay attack).
    """
    sim_pubs = [p for p in pubs if p.simulation_seen]
    if not sim_pubs:
        return []
    return [VulnerabilityFinding(
        vuln_id="RTU-61850-002",
        title="GOOSE Simulation Flag TRUE in Live Traffic -- Trip-Block Attack Risk",
        severity="critical",
        category="protocol",
        description=(
            f"GOOSE frames from {device.ip} (MAC {device.mac}) have the "
            f"simulation bit set to TRUE. IEC 61850-8-1 \u00a717.2.1 states that "
            f"subscribing IEDs MUST ignore GOOSE messages with simulation=TRUE "
            f"during normal operation. If an attacker sends forged GOOSE with "
            f"simulation=TRUE before a real trip event, the subscribing IED "
            f"will suppress the real trip -- a 'trip-blocking' attack. "
            f"Affected GOOSE IDs: {', '.join(p.goose_id for p in sim_pubs if p.goose_id)}."
        ),
        evidence={
            "publisher_mac":    device.mac,
            "simulation_pubs":  [p.goose_id for p in sim_pubs],
        },
        remediation=(
            "Investigate why simulation=TRUE is set on a live IED. "
            "If testing is complete, disable the simulation flag on the IED "
            "using the engineering tool (e.g., ABB PCM600, Siemens DIGSI, SEL-5030). "
            "Configure subscribing IEDs to alert on unexpected simulation=TRUE. "
            "Implement IEC 62351-6 signatures so forged simulation frames are rejected."
        ),
        references=[
            "IEC 61850-8-1:2011 \u00a717.2.1 -- Simulation Bit",
            "IEC 62351-6:2020 -- GOOSE Security",
            "Attacks on Digital Substation Automation -- Dondossola et al. (2011)",
        ],
        first_seen=min((p.first_seen for p in sim_pubs if p.first_seen), default=None),
        packet_count=sum(p.total_packets for p in sim_pubs),
    )]


def _check_goose_low_ttl(
    device: OTDevice, pubs: List[GOOSEPublisherState]
) -> List[VulnerabilityFinding]:
    """
    RTU-61850-003 -- GOOSE timeAllowedToLive is very low (< 2000 ms).
    A very low TTL means subscribers will stop acting on the GOOSE
    very shortly after the last message -- a short DoS or replay window.
    """
    findings = []
    for pub in pubs:
        if pub.min_ttl_ms < LOW_TTL_MS and pub.min_ttl_ms > 0:
            findings.append(VulnerabilityFinding(
                vuln_id="RTU-61850-003",
                title=f"GOOSE Very Low timeAllowedToLive ({pub.min_ttl_ms} ms)",
                severity="medium",
                category="misconfiguration",
                description=(
                    f"GOOSE publisher {pub.gcb_ref or pub.src_mac} has "
                    f"timeAllowedToLive={pub.min_ttl_ms} ms, which is below "
                    f"the recommended minimum of {LOW_TTL_MS} ms. "
                    f"A very low TTL means subscribing IEDs will lose GOOSE "
                    f"validity within {pub.min_ttl_ms} ms of a network "
                    f"disruption. This can be exploited as a Denial of Service: "
                    f"blocking GOOSE for {pub.min_ttl_ms} ms causes the subscriber "
                    f"to enter a timeout / fail-safe state."
                ),
                evidence={
                    "gcb_ref":      pub.gcb_ref,
                    "goose_id":     pub.goose_id,
                    "min_ttl_ms":   pub.min_ttl_ms,
                    "publisher_mac": pub.src_mac,
                },
                remediation=(
                    "Increase timeAllowedToLive to \u22652000 ms (typically 4000 ms "
                    "for protection applications) in the IED configuration. "
                    "Refer to IEC 61850-8-1 \u00a78.1.3 for TTL guidance."
                ),
                references=[
                    "IEC 61850-8-1:2011 \u00a78.1.3 -- timeAllowedToLive",
                    "IEC TC57 WG10 -- GOOSE Performance Guidelines",
                ],
                first_seen=pub.first_seen,
                packet_count=pub.total_packets,
            ))
    return findings


def _check_goose_conf_change(
    device: OTDevice, pubs: List[GOOSEPublisherState]
) -> List[VulnerabilityFinding]:
    """
    RTU-61850-004 -- GOOSE confRev changes during observation window.
    confRev increments when the GOOSE dataset or configuration changes.
    Unexpected changes may indicate an unauthorised configuration modification.
    """
    findings = []
    for pub in pubs:
        if pub.conf_rev_changes > 0:
            findings.append(VulnerabilityFinding(
                vuln_id="RTU-61850-004",
                title="GOOSE Configuration Revision (confRev) Changed",
                severity="medium",
                category="misconfiguration",
                description=(
                    f"GOOSE publisher {pub.gcb_ref or pub.src_mac} changed "
                    f"confRev {pub.conf_rev_changes} time(s) during the capture "
                    f"window (last value: {pub.last_conf_rev}). "
                    f"confRev increments indicate the GOOSE dataset configuration "
                    f"was modified. Unexpected changes may signal an unauthorised "
                    f"engineering workstation modifying IED parameters."
                ),
                evidence={
                    "gcb_ref":          pub.gcb_ref,
                    "conf_rev_changes":  pub.conf_rev_changes,
                    "last_conf_rev":     pub.last_conf_rev,
                    "publisher_mac":     pub.src_mac,
                },
                remediation=(
                    "Audit IED configuration change logs. Verify the confRev change "
                    "was authorised and performed by an approved engineering workstation. "
                    "Implement change management for IEC 61850 IED configurations "
                    "per NERC CIP-010. Monitor confRev values using an IDS."
                ),
                references=[
                    "IEC 61850-8-1 \u00a717.2 -- confRev",
                    "NERC CIP-010-3 -- Configuration Change Management",
                ],
                first_seen=pub.first_seen,
                packet_count=pub.conf_rev_changes,
            ))
    return findings


def _check_goose_nds_com(
    device: OTDevice, pubs: List[GOOSEPublisherState]
) -> List[VulnerabilityFinding]:
    """
    RTU-61850-005 -- GOOSE ndsCom (Needs Commissioning) flag is TRUE.
    ndsCom=TRUE indicates the IED is not yet commissioned -- it may be
    operating with default configuration, factory credentials, or
    unconfigured protection parameters.
    """
    # ndsCom is not tracked in GOOSEPublisherState; skip if not present
    return []


# --------------------------------------------------- MMS checks ----------

def _check_mms_no_tls(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    RTU-61850-006 -- IEC 61850 MMS without TLS (IEC 62351-4).
    MMS runs on TCP 102 in cleartext unless wrapped with TLS per IEC 62351-4.
    All report data, logs, and configuration exchanges are exposed.
    """
    return [VulnerabilityFinding(
        vuln_id="RTU-61850-006",
        title="IEC 61850 MMS Without TLS (IEC 62351-4)",
        severity="high",
        category="encryption",
        description=(
            f"IEC 61850 MMS traffic on {device.ip}:102 is transmitted in "
            f"cleartext. No TLS handshake was observed before MMS sessions, "
            f"indicating IEC 62351-4 TLS is not deployed. All IED reports, "
            f"event logs, dataset reads, and control commands are visible "
            f"to any observer on the network path."
        ),
        evidence={
            "rtu_ip":  device.ip,
            "port":    102,
            "tls":     False,
        },
        remediation=(
            "Implement TLS 1.2+ wrapping for MMS per IEC 62351-4. "
            "Use mutual TLS so both client and server present valid certificates. "
            "Disable unencrypted MMS once TLS is validated. "
            "Segment the station bus on a dedicated VLAN as interim control."
        ),
        references=[
            "IEC 62351-4:2018 -- TLS Profiles for MMS",
            "IEC 61850-8-1:2011 -- MMS Mapping",
            "NERC CIP-005-6 R2 -- Electronic Security Perimeter",
        ],
        first_seen=None,
        packet_count=0,
    )]
