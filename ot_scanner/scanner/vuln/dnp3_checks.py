"""
DNP3 Vulnerability Checks
References: IEEE 1815-2012, IEC 62351-5, ICS-CERT Advisory ICSA-20-049,
            NERC CIP-005, NERC CIP-007
"""
from datetime import datetime
from typing import Dict, List, Optional

from ..models import DNP3SessionState, OTDevice, VulnerabilityFinding


def run_dnp3_checks(
    device: OTDevice,
    sessions: Dict,          # (master_ip, outstation_ip) -> DNP3SessionState
) -> List[VulnerabilityFinding]:
    """Run all DNP3 vulnerability checks for a device. Returns findings list."""
    findings: List[VulnerabilityFinding] = []

    # Collect all sessions where this device is the outstation
    device_sessions = [
        s for s in sessions.values()
        if s.outstation_ip == device.ip
    ]
    if not device_sessions:
        return findings

    findings += _check_no_secure_auth(device, device_sessions)
    findings += _check_unauthenticated_control(device, device_sessions)
    findings += _check_direct_operate(device, device_sessions)
    findings += _check_restart_commands(device, device_sessions)
    findings += _check_file_transfer(device, device_sessions)
    findings += _check_multiple_masters(device, device_sessions)
    findings += _check_dnp3_over_udp(device, device_sessions)
    return findings


# --------------------------------------------------- individual checks ----

def _check_no_secure_auth(
    device: OTDevice, sessions: List[DNP3SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-DNP3-001 -- No DNP3 Secure Authentication observed.
    If control commands or data exchanges occurred without any SA Challenge /
    Reply function codes (FC 32 / FC 33), the session is unauthenticated.
    """
    findings = []
    total_auth  = sum(s.auth_challenges + s.auth_replies + s.auth_aggressive
                      for s in sessions)
    total_ctrl  = sum(len(s.select_commands) + len(s.operate_commands) +
                      len(s.direct_operate)  + len(s.direct_operate_noack)
                      for s in sessions)
    total_pkts  = sum(s.packet_count for s in sessions)

    if total_auth == 0 and total_pkts >= 4:
        findings.append(VulnerabilityFinding(
            vuln_id="RTU-DNP3-001",
            title="No DNP3 Secure Authentication (SAv5/SAv6)",
            severity="high",
            category="authentication",
            description=(
                f"DNP3 traffic on {device.ip} contains no Secure Authentication "
                f"function codes (FC 0x20 Challenge / FC 0x21 Reply / FC 0x83 "
                f"Aggressive Mode). All {total_pkts} observed packets are "
                f"unauthenticated, allowing any device on the network to send "
                f"control commands or spoof measurement responses."
            ),
            evidence={
                "total_packets":     total_pkts,
                "auth_challenges":   0,
                "auth_replies":      0,
                "control_commands":  total_ctrl,
                "sessions_checked":  len(sessions),
            },
            remediation=(
                "Enable DNP3 Secure Authentication v5 or v6 (IEC 62351-5) on all "
                "master and outstation devices. Configure pre-shared keys (SAv5) or "
                "certificate-based authentication (SAv6). Where SA is not supported, "
                "implement compensating controls: dedicated OT VLANs, firewall rules "
                "whitelisting master IP addresses, and IDS monitoring for unexpected "
                "DNP3 sources."
            ),
            references=[
                "IEEE 1815-2012 Annex D -- DNP3 Secure Authentication",
                "IEC 62351-5 -- Security for DNP3",
                "NERC CIP-005-6 R2 -- Electronic Security Perimeter",
                "ICS-CERT Advisory ICSA-20-049",
            ],
            mitre_attack=["T0859", "T0869"],  # Valid Accounts, Std App Layer Protocol
            first_seen=min((s.first_seen for s in sessions if s.first_seen),
                           default=None),
            packet_count=total_pkts,
        ))
    return findings


def _check_unauthenticated_control(
    device: OTDevice, sessions: List[DNP3SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-DNP3-002 -- Control commands sent without prior SA challenge/reply.
    Even if SA is partially configured, if control commands arrive before
    any auth exchange that session window is unauthenticated.
    """
    findings = []
    for sess in sessions:
        total_ctrl = (len(sess.select_commands) + len(sess.operate_commands) +
                      len(sess.direct_operate) + len(sess.direct_operate_noack))
        has_auth   = (sess.auth_challenges + sess.auth_replies + sess.auth_aggressive) > 0
        if total_ctrl > 0 and not has_auth:
            findings.append(VulnerabilityFinding(
                vuln_id="RTU-DNP3-002",
                title="Unauthenticated DNP3 Control Commands",
                severity="critical",
                category="command-security",
                description=(
                    f"Master {sess.master_ip} sent {total_ctrl} control command(s) "
                    f"(Select/Operate/Direct Operate) to outstation {device.ip} "
                    f"(addr {sess.outstation_addr}) without any preceding "
                    f"authentication exchange. An adversary with network access "
                    f"could replay or forge control commands."
                ),
                evidence={
                    "master_ip":         sess.master_ip,
                    "outstation_addr":   sess.outstation_addr,
                    "select_count":      len(sess.select_commands),
                    "operate_count":     len(sess.operate_commands),
                    "direct_operate":    len(sess.direct_operate),
                    "auth_exchanges":    0,
                    "first_command_ts":  _first_ts(
                        sess.select_commands + sess.operate_commands + sess.direct_operate),
                },
                remediation=(
                    "Require DNP3 SA authentication before any control function codes "
                    "(FC 3-6). Configure the DNP3 master to challenge outstations and "
                    "configure outstations to reject unauthenticated control commands. "
                    "See IEEE 1815-2012 Section 7.4."
                ),
                references=[
                    "IEEE 1815-2012 \u00a77.4 -- Authentication Required for FC 3-6",
                    "IEC 62351-5 \u00a78 -- Authenticated Operations",
                    "NERC CIP-007-6 R5 -- System Access Controls",
                ],
                mitre_attack=["T0855"],  # Unauthorized Command Message
                first_seen=sess.first_seen,
                packet_count=sess.packet_count,
            ))
    return findings


def _check_direct_operate(
    device: OTDevice, sessions: List[DNP3SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-DNP3-003 -- Direct Operate (FC 5) bypasses Select-Before-Operate.
    SBO (Select then Operate) is a two-step safety mechanism. Direct Operate
    collapses this to one step -- increasing the risk of accidental or malicious
    single-command tripping of breakers or other actuators.
    """
    findings = []
    for sess in sessions:
        do_count = len(sess.direct_operate) + len(sess.direct_operate_noack)
        if do_count > 0:
            findings.append(VulnerabilityFinding(
                vuln_id="RTU-DNP3-003",
                title="Direct Operate (FC5) Bypasses Select-Before-Operate Safety",
                severity="high",
                category="command-security",
                description=(
                    f"Master {sess.master_ip} used Direct Operate (FC 0x05) "
                    f"{do_count} time(s) against outstation {device.ip}. "
                    f"Direct Operate skips the mandatory SBO two-step confirmation, "
                    f"allowing a single packet to trip a breaker or actuate a switch "
                    f"without an intermediate check."
                ),
                evidence={
                    "master_ip":              sess.master_ip,
                    "direct_operate_count":   len(sess.direct_operate),
                    "direct_operate_noack":   len(sess.direct_operate_noack),
                    "sample_command":         sess.direct_operate[0] if sess.direct_operate else None,
                },
                remediation=(
                    "Configure the RTU/FRTU to reject Direct Operate (FC 5) and require "
                    "Select-Before-Operate (FC 3 then FC 4) for all actuator control. "
                    "Configure the master station to use SBO. Review whether Direct "
                    "Operate is genuinely required for any control point."
                ),
                references=[
                    "IEEE 1815-2012 \u00a74.4.4 -- Select-Before-Operate",
                    "IEC 62351-5 \u00a79 -- Control Command Security",
                    "NERC CIP-007-6 R5",
                ],
                mitre_attack=["T0855", "T0831"],  # Unauthorized Cmd Msg, Manipulation of Control
                first_seen=sess.first_seen,
                packet_count=do_count,
            ))
    return findings


def _check_restart_commands(
    device: OTDevice, sessions: List[DNP3SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-DNP3-004 -- Cold/Warm Restart or Stop/Start Application commands.
    These maintenance function codes can disrupt field operations if issued
    by a rogue master and should be authenticated and logged.
    """
    findings = []
    for sess in sessions:
        cold  = sess.cold_restarts
        warm  = sess.warm_restarts
        stop  = sess.stop_app
        start = sess.start_app
        init  = sess.init_data
        total = cold + warm + stop + start + init
        if total > 0:
            has_auth = (sess.auth_challenges + sess.auth_replies + sess.auth_aggressive) > 0
            sev = "high" if not has_auth else "medium"
            findings.append(VulnerabilityFinding(
                vuln_id="RTU-DNP3-004",
                title="DNP3 Maintenance/Restart Commands Observed",
                severity=sev,
                category="availability",
                description=(
                    f"Master {sess.master_ip} sent {total} maintenance command(s) "
                    f"to outstation {device.ip}: Cold Restart\u00d7{cold}, "
                    f"Warm Restart\u00d7{warm}, Stop App\u00d7{stop}, Start App\u00d7{start}, "
                    f"Init Data\u00d7{init}. "
                    + ("No authentication was observed for this session." if not has_auth
                       else "Session had authentication present.")
                ),
                evidence={
                    "master_ip":    sess.master_ip,
                    "cold_restart": cold,
                    "warm_restart": warm,
                    "stop_app":     stop,
                    "start_app":    start,
                    "init_data":    init,
                    "authenticated": has_auth,
                },
                remediation=(
                    "Restrict Cold/Warm Restart (FC 13/14) and Application control "
                    "(FC 17/18) to authenticated sessions only. Whitelist authorised "
                    "maintenance workstations at the firewall. Enable logging of all "
                    "maintenance function codes at the RTU."
                ),
                references=[
                    "IEEE 1815-2012 \u00a74.4.5 -- Restart Functions",
                    "IEC 62351-5 \u00a78.3 -- Authentication for Critical Functions",
                    "NERC CIP-010-3 -- Configuration Change Management",
                ],
                mitre_attack=["T0816", "T0881"],  # Device Restart/Shutdown, Service Stop
                first_seen=sess.first_seen,
                packet_count=total,
            ))
    return findings


def _check_file_transfer(
    device: OTDevice, sessions: List[DNP3SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-DNP3-005 -- DNP3 File Transfer function codes observed.
    File transfer (FC 25-30) can deliver firmware updates or configuration
    files. If unauthenticated, this is a firmware injection vector.
    """
    findings = []
    for sess in sessions:
        opens   = len(sess.file_opens)
        closes  = sess.file_closes
        deletes = sess.file_deletes
        total   = opens + closes + deletes + sess.file_aborts
        if total > 0:
            has_auth = (sess.auth_challenges + sess.auth_replies) > 0
            sev = "critical" if not has_auth else "high"
            file_names = [f.get("details", {}).get("filename", "?")
                          for f in sess.file_opens if f]
            findings.append(VulnerabilityFinding(
                vuln_id="RTU-DNP3-005",
                title="DNP3 File Transfer -- Potential Firmware/Config Injection",
                severity=sev,
                category="protocol",
                description=(
                    f"DNP3 File Transfer operations detected between master "
                    f"{sess.master_ip} and outstation {device.ip}: "
                    f"Open\u00d7{opens}, Close\u00d7{closes}, Delete\u00d7{deletes}. "
                    f"File transfer can deliver firmware, configuration changes, "
                    f"or malicious code to the RTU/FRTU. "
                    + ("Session was NOT authenticated." if not has_auth else
                       "Session had authentication.")
                ),
                evidence={
                    "master_ip":      sess.master_ip,
                    "file_opens":     opens,
                    "file_closes":    closes,
                    "file_deletes":   deletes,
                    "file_aborts":    sess.file_aborts,
                    "file_names":     file_names[:5],
                    "authenticated":  has_auth,
                },
                remediation=(
                    "Authenticate all DNP3 File Transfer sessions (IEC 62351-5 \u00a710). "
                    "Implement firmware integrity validation on the RTU. "
                    "Log all file transfer events and alert on unexpected sources. "
                    "Restrict file transfer to a designated engineering workstation IP."
                ),
                references=[
                    "IEEE 1815-2012 \u00a74.5 -- File Transfer",
                    "IEC 62351-5 \u00a710 -- File Transfer Security",
                    "ICS-CERT Advisory ICSA-16-084 -- DNP3 File Transfer Vulnerability",
                ],
                mitre_attack=["T0839", "T0843"],  # Module Firmware, Program Download
                first_seen=sess.first_seen,
                packet_count=total,
            ))
    return findings


def _check_multiple_masters(
    device: OTDevice, sessions: List[DNP3SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-DNP3-006 -- Multiple master stations communicating with the same RTU.
    Legitimate SCADA systems typically use one (or a primary/backup pair) of
    master stations. Additional masters may indicate a rogue device.
    """
    findings = []
    masters = {s.master_ip for s in sessions}
    if len(masters) > 2:
        findings.append(VulnerabilityFinding(
            vuln_id="RTU-DNP3-006",
            title="Multiple DNP3 Masters -- Potential Rogue Master Station",
            severity="high",
            category="misconfiguration",
            description=(
                f"Outstation {device.ip} (DNP3 addr {device.dnp3_address}) is "
                f"communicating with {len(masters)} distinct master stations: "
                f"{', '.join(sorted(masters))}. "
                f"Legitimate SCADA architectures typically use \u22642 masters "
                f"(primary + backup). Additional masters may represent rogue "
                f"devices, misconfigured HMIs, or an active intrusion."
            ),
            evidence={
                "master_ips":    sorted(masters),
                "master_count":  len(masters),
            },
            remediation=(
                "Configure the RTU to accept commands only from authorised master "
                "IP addresses (IP allowlist at the RTU or upstream firewall). "
                "Investigate unexpected master IPs immediately. Implement DNP3 SA "
                "so that unenrolled masters cannot authenticate."
            ),
            references=[
                "IEC 62351-5 \u00a76 -- Access Control",
                "NERC CIP-005-6 R2.4 -- Deny by default",
                "ICS-CERT Alert TA18-074A -- Rogue HMI",
            ],
            mitre_attack=["T0848"],  # Rogue Master
            first_seen=min((s.first_seen for s in sessions if s.first_seen),
                           default=None),
            packet_count=sum(s.packet_count for s in sessions),
        ))
    return findings


def _check_dnp3_over_udp(
    device: OTDevice, sessions: List[DNP3SessionState]
) -> List[VulnerabilityFinding]:
    """
    RTU-DNP3-007 -- DNP3 transported over UDP (connectionless).
    DNP3/UDP lacks TCP's connection-oriented sequence numbers, making
    spoofing and replay attacks significantly easier.
    """
    findings = []
    udp_sessions = [s for s in sessions if s.over_udp]
    if udp_sessions:
        findings.append(VulnerabilityFinding(
            vuln_id="RTU-DNP3-007",
            title="DNP3 Transported over UDP (Stateless / Replay Risk)",
            severity="medium",
            category="protocol",
            description=(
                f"DNP3 traffic to outstation {device.ip} was observed over UDP. "
                f"UDP provides no connection state, sequence numbers, or retransmission, "
                f"making packet replay and source-spoofing attacks easier than over TCP. "
                f"Control commands over UDP are particularly concerning."
            ),
            evidence={
                "udp_session_masters": [s.master_ip for s in udp_sessions],
            },
            remediation=(
                "Migrate DNP3 communications to TCP where possible. If UDP is "
                "required (e.g., radio links), ensure DNP3 Secure Authentication "
                "is enabled to provide replay protection at the application layer."
            ),
            references=[
                "IEEE 1815-2012 \u00a710 -- DNP3 over UDP",
                "IEC 62351-5 \u00a77.2 -- Transport Independence",
            ],
            mitre_attack=["T0830"],  # Man in the Middle
            first_seen=min((s.first_seen for s in udp_sessions if s.first_seen),
                           default=None),
            packet_count=sum(s.packet_count for s in udp_sessions),
        ))
    return findings


# -- helpers -------------------------------------------------------------------

def _first_ts(events: list) -> Optional[str]:
    for ev in events:
        if isinstance(ev, dict) and ev.get("ts"):
            return ev["ts"]
    return None
