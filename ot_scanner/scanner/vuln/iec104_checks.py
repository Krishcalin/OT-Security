"""
IEC 60870-5-104 Vulnerability Checks
References: IEC 62351-3, IEC 62351-5, NERC CIP-005, NERC CIP-007,
            ENTSO-E Network Code on Cybersecurity
"""
from typing import Dict, List

from ..models import IEC104SessionState, OTDevice, VulnerabilityFinding


def run_iec104_checks(
    device: OTDevice,
    sessions: Dict,          # (master_ip, rtu_ip) -> IEC104SessionState
) -> List[VulnerabilityFinding]:
    """Run all IEC 60870-5-104 checks for a device."""
    findings: List[VulnerabilityFinding] = []
    device_sessions = [
        s for s in sessions.values() if s.rtu_ip == device.ip
    ]
    if not device_sessions:
        return findings

    findings += _check_no_tls(device, device_sessions)
    findings += _check_multiple_masters(device, device_sessions)
    findings += _check_unauthenticated_control(device, device_sessions)
    findings += _check_clock_sync(device, device_sessions)
    findings += _check_general_interrogation(device, device_sessions)
    return findings


# -------------------------------------------------- individual checks ----

def _check_no_tls(
    device: OTDevice, sessions: List[IEC104SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-104-001 -- IEC 60870-5-104 without IEC 62351-3 TLS wrapper.
    Standard IEC 104 on TCP/2404 carries all data in cleartext.
    TLS (IEC 62351-3) provides confidentiality and peer authentication
    but is not detectable in the PCAP once established -- so absence of
    TLS negotiation (no TLS ClientHello on port 2404) is the indicator.
    """
    total_pkts = sum(s.packet_count for s in sessions)
    # We flag this for ALL IEC-104 devices because IEC 62351-3 TLS
    # would show a TLS handshake on port 2404 before any IEC-104 frames.
    # If we see raw APDU bytes (start 0x68) without TLS, it is cleartext.
    return [VulnerabilityFinding(
        vuln_id="RTU-104-001",
        title="IEC 60870-5-104 Without TLS (IEC 62351-3)",
        severity="high",
        category="encryption",
        description=(
            f"IEC 60870-5-104 communications on {device.ip}:{2404} are "
            f"transmitted in cleartext. No TLS handshake was observed before "
            f"the APDU traffic, indicating IEC 62351-3 TLS is not deployed. "
            f"All measurement data, control commands, and STARTDT sessions "
            f"are visible to any observer on the network path."
        ),
        evidence={
            "rtu_ip":       device.ip,
            "total_packets": total_pkts,
            "master_ips":   sorted({s.master_ip for s in sessions}),
        },
        remediation=(
            "Wrap IEC 60870-5-104 sessions in TLS 1.2+ per IEC 62351-3. "
            "Use mutual TLS (both master and RTU present certificates) to "
            "prevent rogue master connections. Ensure the RTU firmware supports "
            "IEC 62351-3; upgrade if not. As an interim control, isolate the "
            "communication path on a dedicated VLAN with firewall ACLs."
        ),
        references=[
            "IEC 62351-3 -- TLS for IEC 60870-5-104",
            "IEC 62351-5 -- Security for DNP3/IEC 60870-5",
            "ENTSO-E Network Code on Cybersecurity -- Article 33",
            "NERC CIP-005-6 R2 -- Electronic Security Perimeter",
        ],
        mitre_attack=["T0842", "T0830"],  # Network Sniffing, Man in the Middle
        first_seen=min((s.first_seen for s in sessions if s.first_seen), default=None),
        packet_count=total_pkts,
    )]


def _check_multiple_masters(
    device: OTDevice, sessions: List[IEC104SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-104-002 -- Multiple master stations sending STARTDT to the same RTU.
    IEC 104 allows multiple parallel connections but a legitimate architecture
    has a primary and optionally one redundant master. More indicates risk.
    """
    findings = []
    masters = {s.master_ip for s in sessions if s.startdt_count > 0}
    if len(masters) > 2:
        findings.append(VulnerabilityFinding(
            vuln_id="RTU-104-002",
            title="Multiple IEC 104 Masters -- Potential Rogue Connection",
            severity="high",
            category="misconfiguration",
            description=(
                f"RTU {device.ip} received STARTDT from {len(masters)} distinct "
                f"master stations: {', '.join(sorted(masters))}. "
                f"Normal SCADA architectures use \u22642 masters (primary + hot standby). "
                f"Additional STARTDT sources may indicate a rogue master, "
                f"misconfigured HMI, or an unauthorised control centre connection."
            ),
            evidence={
                "master_ips":   sorted(masters),
                "master_count": len(masters),
                "startdt_counts": {
                    s.master_ip: s.startdt_count for s in sessions
                },
            },
            remediation=(
                "Restrict IEC 104 STARTDT acceptance to authorised master IPs "
                "using RTU connection filtering or upstream firewall rules. "
                "Apply IEC 62351-3 TLS with mutual authentication so only "
                "certificate-enrolled masters can establish sessions."
            ),
            references=[
                "IEC 60870-5-104:2006 \u00a78 -- Multiple Connections",
                "IEC 62351-3 -- Mutual TLS Authentication",
                "NERC CIP-005-6 R2.4",
            ],
            mitre_attack=["T0848"],  # Rogue Master
            first_seen=min((s.first_seen for s in sessions if s.first_seen), default=None),
            packet_count=sum(s.packet_count for s in sessions),
        ))
    return findings


def _check_unauthenticated_control(
    device: OTDevice, sessions: List[IEC104SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-104-003 -- Control commands (C_SC, C_DC, C_SE) in cleartext IEC 104.
    Without TLS, switching commands and set-point commands are fully visible
    and can be replayed or forged by any network observer.
    """
    findings = []
    for sess in sessions:
        total_ctrl = (len(sess.single_commands) + len(sess.double_commands) +
                      len(sess.regulating_step) + len(sess.setpoint_commands) +
                      len(sess.bitstring_commands))
        if total_ctrl > 0:
            findings.append(VulnerabilityFinding(
                vuln_id="RTU-104-003",
                title="Cleartext IEC 104 Control Commands (Switch/Set-point)",
                severity="critical",
                category="command-security",
                description=(
                    f"Master {sess.master_ip} sent {total_ctrl} control command(s) "
                    f"to RTU {device.ip} over unencrypted IEC 104: "
                    f"Single Cmd (C_SC)\u00d7{len(sess.single_commands)}, "
                    f"Double Cmd (C_DC)\u00d7{len(sess.double_commands)}, "
                    f"Set-point\u00d7{len(sess.setpoint_commands)}, "
                    f"Regulating\u00d7{len(sess.regulating_step)}. "
                    f"An adversary can observe command patterns and replay or "
                    f"forge switching operations (e.g., open/close a circuit breaker)."
                ),
                evidence={
                    "master_ip":       sess.master_ip,
                    "single_cmd":      len(sess.single_commands),
                    "double_cmd":      len(sess.double_commands),
                    "set_point_cmd":   len(sess.setpoint_commands),
                    "regulating_step": len(sess.regulating_step),
                    "common_address":  sess.common_address,
                },
                remediation=(
                    "Deploy IEC 62351-3 TLS to encrypt all IEC 104 control sessions. "
                    "Implement IEC 62351-5 application-level authentication for "
                    "control commands. As an interim measure, restrict control command "
                    "sources to specific authorised IP addresses."
                ),
                references=[
                    "IEC 62351-3 -- TLS for 60870-5-104",
                    "IEC 62351-5 \u00a78 -- Authenticated Control Commands",
                    "ICS-CERT Advisory ICSA-14-084 -- IEC 104 Replay Vulnerability",
                ],
                mitre_attack=["T0855", "T0831"],  # Unauthorized Cmd Msg, Manipulation of Control
                first_seen=sess.first_seen,
                packet_count=total_ctrl,
            ))
    return findings


def _check_clock_sync(
    device: OTDevice, sessions: List[IEC104SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-104-004 -- Clock Synchronisation (C_CS_NA, type 103) without TLS.
    Unauthenticated clock sync allows an attacker to manipulate RTU
    timestamps, causing event records to be falsified and potentially
    bypassing time-based protection coordination.
    """
    findings = []
    for sess in sessions:
        if sess.clock_syncs > 0:
            findings.append(VulnerabilityFinding(
                vuln_id="RTU-104-004",
                title="Unauthenticated Clock Synchronisation (C_CS_NA Type 103)",
                severity="medium",
                category="protocol",
                description=(
                    f"Master {sess.master_ip} sent {sess.clock_syncs} Clock "
                    f"Synchronisation command(s) (C_CS_NA, Type 103) to "
                    f"RTU {device.ip} over an unauthenticated IEC 104 session. "
                    f"An attacker could forge clock sync frames to manipulate "
                    f"event timestamps, disrupt time-based relay coordination, "
                    f"or invalidate forensic logs."
                ),
                evidence={
                    "master_ip":     sess.master_ip,
                    "clock_syncs":   sess.clock_syncs,
                    "common_address": sess.common_address,
                },
                remediation=(
                    "Use an authenticated NTP/PTP source for RTU clock synchronisation "
                    "instead of IEC 104 C_CS_NA. If C_CS_NA must be used, deploy "
                    "IEC 62351-3 TLS to authenticate the clock source."
                ),
                references=[
                    "IEC 60870-5-104:2006 \u00a78.9 -- Clock Synchronization",
                    "IEC 62351-3 -- Session Authentication",
                ],
                mitre_attack=["T0836"],  # Modify Parameter
                first_seen=sess.first_seen,
                packet_count=sess.clock_syncs,
            ))
    return findings


def _check_general_interrogation(
    device: OTDevice, sessions: List[IEC104SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-104-005 -- Frequent General Interrogation from unexpected sources.
    GI (type 100) forces the RTU to transmit its complete data state --
    if initiated by an unauthorised master it is an information gathering
    technique and can also cause bandwidth saturation.
    """
    findings = []
    for sess in sessions:
        if sess.general_interrogations > 20:
            findings.append(VulnerabilityFinding(
                vuln_id="RTU-104-005",
                title="Excessive General Interrogation (C_IC_NA) Requests",
                severity="low",
                category="availability",
                description=(
                    f"Master {sess.master_ip} sent {sess.general_interrogations} "
                    f"General Interrogation (C_IC_NA, Type 100) requests to "
                    f"RTU {device.ip}. Frequent GI can saturate RTU resources "
                    f"and the communication link, and may indicate an "
                    f"unauthorised data-harvesting client."
                ),
                evidence={
                    "master_ip":              sess.master_ip,
                    "general_interrogations": sess.general_interrogations,
                },
                remediation=(
                    "Verify the master IP is authorised. Rate-limit General "
                    "Interrogation at the RTU configuration. If the source is "
                    "unexpected, investigate and block at the firewall."
                ),
                references=["IEC 60870-5-104:2006 \u00a78.8 -- General Interrogation"],
                mitre_attack=["T0801", "T0814"],  # Monitor Process State, Denial of Service
                first_seen=sess.first_seen,
                packet_count=sess.general_interrogations,
            ))
    return findings
