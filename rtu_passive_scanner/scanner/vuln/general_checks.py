"""
General RTU / FRTU Vulnerability & Misconfiguration Checks
Applies across all protocols and device types.
References: IEC 62443-3-3, NERC CIP-005/007, ICS-CERT Advisories
"""
from typing import List

from ..models import RTUDevice, VulnerabilityFinding

# Protocols that are fundamentally unencrypted at the application layer
UNENCRYPTED_PROTOCOLS = {
    "DNP3",
    "IEC 60870-5-104",
    "IEC 61850 MMS",
    "Modbus/TCP",
    "SEL Fast Message",
}

# Protocols whose exclusive use points to single-vendor environments
EXCLUSIVE_PROTOCOLS = {
    "SEL Fast Message":       "Schweitzer Engineering Laboratories",
    "MELSEC MC Protocol":     "Mitsubishi Electric",
    "Omron FINS":             "Omron",
}


def run_general_checks(device: RTUDevice) -> List[VulnerabilityFinding]:
    """Run protocol-agnostic RTU checks."""
    findings: List[VulnerabilityFinding] = []
    findings += _check_unencrypted_protocols(device)
    findings += _check_multiple_protocols(device)
    findings += _check_no_protocols_identified(device)
    findings += _check_many_peers(device)
    return findings


# ─────────────────────────────────────────────────── individual checks ────

def _check_unencrypted_protocols(device: RTUDevice) -> List[VulnerabilityFinding]:
    """
    RTU-GEN-001 — Device running one or more unencrypted industrial protocols.
    This is an informational finding summarising total cleartext exposure.
    """
    findings = []
    exposed = [p for p in device.get_protocol_names() if p in UNENCRYPTED_PROTOCOLS]
    if exposed:
        findings.append(VulnerabilityFinding(
            vuln_id="RTU-GEN-001",
            title="Cleartext Industrial Protocols Expose OT Traffic",
            severity="high",
            category="encryption",
            description=(
                f"Device {device.ip} is communicating using "
                f"{len(exposed)} unencrypted industrial protocol(s): "
                f"{', '.join(exposed)}. "
                f"All operational data (measurements, alarms, events) and "
                f"control commands are transmitted in plaintext, exposing them "
                f"to eavesdropping, replay, and man-in-the-middle attacks by any "
                f"host on the same network segment."
            ),
            evidence={
                "unencrypted_protocols": exposed,
                "total_protocols":       len(device.protocols),
            },
            remediation=(
                "Apply encryption at the session layer: IEC 62351-3 TLS for "
                "IEC 104, IEC 62351-5 SA for DNP3, IEC 62351-4 TLS for MMS. "
                "Where encryption is not natively supported, use an encrypted "
                "tunnel (IPsec, TLS proxy) between master and RTU. "
                "Enforce network segmentation — RTU/FRTU traffic must remain "
                "on dedicated OT VLANs, isolated from IT networks."
            ),
            references=[
                "IEC 62351 (series) — Security for Power System Communications",
                "IEC 62443-3-3 SR 4.3 — Use of Cryptography",
                "NERC CIP-007-6 R5 — System Access Controls",
            ],
            first_seen=device.first_seen,
            packet_count=device.packet_count,
        ))
    return findings


def _check_multiple_protocols(device: RTUDevice) -> List[VulnerabilityFinding]:
    """
    RTU-GEN-002 — Device running 3+ distinct industrial protocols.
    Each additional protocol is an extra attack surface. RTUs/FRTUs should
    expose only the protocols genuinely required for their role.
    """
    findings = []
    proto_names = device.get_protocol_names()
    if len(proto_names) >= 3:
        findings.append(VulnerabilityFinding(
            vuln_id="RTU-GEN-002",
            title=f"Excessive Industrial Protocol Exposure ({len(proto_names)} Protocols)",
            severity="medium",
            category="misconfiguration",
            description=(
                f"Device {device.ip} exposes {len(proto_names)} industrial protocols: "
                f"{', '.join(proto_names)}. "
                f"Each protocol is a potential attack vector. RTUs and FRTUs should "
                f"expose only the protocols required for their operational role. "
                f"Unused protocol services should be disabled to reduce the attack surface."
            ),
            evidence={
                "protocols": proto_names,
                "count":     len(proto_names),
            },
            remediation=(
                "Audit which protocols are operationally required. Disable unused "
                "protocol services at the RTU configuration level. Document the "
                "authorised protocol set in the asset inventory. Apply firewall "
                "rules to block unauthorised protocol ports."
            ),
            references=[
                "IEC 62443-3-3 SR 7.7 — Least Functionality",
                "NERC CIP-007-6 R1 — Ports and Services",
                "NIST SP 800-82 Rev 3 §6.2.5",
            ],
            first_seen=device.first_seen,
            packet_count=device.packet_count,
        ))
    return findings


def _check_no_protocols_identified(
    device: RTUDevice
) -> List[VulnerabilityFinding]:
    """
    RTU-GEN-003 — Device on known OT ports but no protocol matched.
    Could indicate a custom / obfuscated protocol or a misconfigured device.
    """
    findings = []
    if device.open_ports and not device.protocols:
        findings.append(VulnerabilityFinding(
            vuln_id="RTU-GEN-003",
            title="Device on OT Ports — Protocol Unidentified",
            severity="low",
            category="misconfiguration",
            description=(
                f"Device {device.ip} is listening on known OT port(s) "
                f"{sorted(device.open_ports)} but no industrial protocol was "
                f"successfully parsed. This may indicate a non-standard firmware "
                f"version, a custom protocol variant, or a misconfigured device. "
                f"Manual inspection of the PCAP is recommended."
            ),
            evidence={
                "open_ports":   sorted(device.open_ports),
                "packet_count": device.packet_count,
            },
            remediation=(
                "Perform a manual protocol analysis of the captured traffic. "
                "Verify the device's role and authorised protocol configuration. "
                "If the protocol cannot be identified, treat the device as "
                "untrusted and isolate pending investigation."
            ),
            references=["IEC 62443-2-1 §4.3.3 — Asset Identification"],
            first_seen=device.first_seen,
            packet_count=device.packet_count,
        ))
    return findings


def _check_many_peers(device: RTUDevice) -> List[VulnerabilityFinding]:
    """
    RTU-GEN-004 — RTU communicating with an unusually large number of peers.
    RTUs are field devices with a small, fixed set of authorised communication
    partners. Excessive peers may indicate network scanning, bridging, or
    a compromised device being used as a pivot.
    """
    findings = []
    peer_count = len(device.communicating_with)
    if peer_count > 10:
        findings.append(VulnerabilityFinding(
            vuln_id="RTU-GEN-004",
            title=f"Unusual Number of Communication Peers ({peer_count})",
            severity="medium",
            category="misconfiguration",
            description=(
                f"RTU/FRTU {device.ip} communicated with {peer_count} distinct "
                f"IP addresses during the capture period. Field devices such as "
                f"RTUs and FRTUs typically have ≤5 legitimate communication peers "
                f"(1–2 SCADA masters, NTP, syslog, engineering workstation). "
                f"Excessive peers may indicate network scanning activity, a "
                f"compromised device being used as a pivot, or network misconfiguration."
            ),
            evidence={
                "peer_count": peer_count,
                "peers":      sorted(device.communicating_with)[:20],
            },
            remediation=(
                "Review and whitelist the authorised communication peers for this "
                "device. Implement firewall rules or RTU IP filtering to restrict "
                "connections to known-good addresses. Investigate unexpected peers."
            ),
            references=[
                "NERC CIP-005-6 R2 — Electronic Security Perimeter",
                "IEC 62443-3-3 SR 5.1 — Network Segmentation",
            ],
            first_seen=device.first_seen,
            packet_count=device.packet_count,
        ))
    return findings
