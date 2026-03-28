"""
General OT Device Vulnerability & Misconfiguration Checks
Applies across all protocols and device types — including new OPC-UA and MQTT checks.
References: IEC 62443-3-3, NERC CIP-005/007, ICS-CERT Advisories,
            OPC 10000-2 (OPC-UA Security), OASIS MQTT v5.0
"""
from typing import List

from ..models import OTDevice, VulnerabilityFinding

# Protocols that are fundamentally unencrypted at the application layer
UNENCRYPTED_PROTOCOLS = {
    "DNP3",
    "IEC 60870-5-104",
    "IEC 61850 MMS",
    "Modbus/TCP",
    "SEL Fast Message",
    "BACnet/IP",
    "MQTT",
    "PROFINET RT",
}

# Protocols whose exclusive use points to single-vendor environments
EXCLUSIVE_PROTOCOLS = {
    "SEL Fast Message":       "Schweitzer Engineering Laboratories",
    "MELSEC MC Protocol":     "Mitsubishi Electric",
    "Omron FINS":             "Omron",
}


def run_general_checks(device: OTDevice) -> List[VulnerabilityFinding]:
    """Run protocol-agnostic OT device checks plus OPC-UA and MQTT checks."""
    findings: List[VulnerabilityFinding] = []
    findings += _check_unencrypted_protocols(device)
    findings += _check_multiple_protocols(device)
    findings += _check_no_protocols_identified(device)
    findings += _check_many_peers(device)
    findings += _check_opcua_no_security(device)
    findings += _check_mqtt_no_tls(device)
    findings += _check_mqtt_no_auth(device)
    findings += _check_remote_access_in_ot(device)
    findings += _check_database_in_ot(device)
    findings += _check_telnet_in_ot(device)
    findings += _check_file_sharing_in_ot(device)
    findings += _check_high_it_protocol_count(device)
    return findings


# --------------------------------------------------- individual checks ----

def _check_unencrypted_protocols(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-GEN-001 -- Device running one or more unencrypted industrial protocols.
    This is an informational finding summarising total cleartext exposure.
    """
    findings = []
    exposed = [p for p in device.get_protocol_names() if p in UNENCRYPTED_PROTOCOLS]
    if exposed:
        findings.append(VulnerabilityFinding(
            vuln_id="OT-GEN-001",
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
                "IEC 104, IEC 62351-5 SA for DNP3, IEC 62351-4 TLS for MMS, "
                "OPC-UA Security Policy for OPC-UA, MQTT over TLS (port 8883) "
                "for MQTT, BACnet/SC (Secure Connect) for BACnet. "
                "Where encryption is not natively supported, use an encrypted "
                "tunnel (IPsec, TLS proxy) between master and device. "
                "Enforce network segmentation -- OT device traffic must remain "
                "on dedicated OT VLANs, isolated from IT networks."
            ),
            references=[
                "IEC 62351 (series) -- Security for Power System Communications",
                "IEC 62443-3-3 SR 4.3 -- Use of Cryptography",
                "NERC CIP-007-6 R5 -- System Access Controls",
            ],
            first_seen=device.first_seen,
            packet_count=device.packet_count,
        ))
    return findings


def _check_multiple_protocols(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-GEN-002 -- Device running 3+ distinct industrial protocols.
    Each additional protocol is an extra attack surface. OT devices should
    expose only the protocols genuinely required for their role.
    """
    findings = []
    proto_names = device.get_protocol_names()
    if len(proto_names) >= 3:
        findings.append(VulnerabilityFinding(
            vuln_id="OT-GEN-002",
            title=f"Excessive Industrial Protocol Exposure ({len(proto_names)} Protocols)",
            severity="medium",
            category="misconfiguration",
            description=(
                f"Device {device.ip} exposes {len(proto_names)} industrial protocols: "
                f"{', '.join(proto_names)}. "
                f"Each protocol is a potential attack vector. OT devices should "
                f"expose only the protocols required for their operational role. "
                f"Unused protocol services should be disabled to reduce the attack surface."
            ),
            evidence={
                "protocols": proto_names,
                "count":     len(proto_names),
            },
            remediation=(
                "Audit which protocols are operationally required. Disable unused "
                "protocol services at the device configuration level. Document the "
                "authorised protocol set in the asset inventory. Apply firewall "
                "rules to block unauthorised protocol ports."
            ),
            references=[
                "IEC 62443-3-3 SR 7.7 -- Least Functionality",
                "NERC CIP-007-6 R1 -- Ports and Services",
                "NIST SP 800-82 Rev 3 \u00a76.2.5",
            ],
            first_seen=device.first_seen,
            packet_count=device.packet_count,
        ))
    return findings


def _check_no_protocols_identified(
    device: OTDevice
) -> List[VulnerabilityFinding]:
    """
    OT-GEN-003 -- Device on known OT ports but no protocol matched.
    Could indicate a custom / obfuscated protocol or a misconfigured device.
    """
    findings = []
    if device.open_ports and not device.protocols:
        findings.append(VulnerabilityFinding(
            vuln_id="OT-GEN-003",
            title="Device on OT Ports -- Protocol Unidentified",
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
            references=["IEC 62443-2-1 \u00a74.3.3 -- Asset Identification"],
            first_seen=device.first_seen,
            packet_count=device.packet_count,
        ))
    return findings


def _check_many_peers(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-GEN-004 -- OT device communicating with an unusually large number of peers.
    OT field devices have a small, fixed set of authorised communication
    partners. Excessive peers may indicate network scanning, bridging, or
    a compromised device being used as a pivot.
    """
    findings = []
    peer_count = len(device.communicating_with)
    if peer_count > 10:
        findings.append(VulnerabilityFinding(
            vuln_id="OT-GEN-004",
            title=f"Unusual Number of Communication Peers ({peer_count})",
            severity="medium",
            category="misconfiguration",
            description=(
                f"OT device {device.ip} communicated with {peer_count} distinct "
                f"IP addresses during the capture period. Field devices such as "
                f"PLCs, RTUs, and IEDs typically have \u22645 legitimate communication "
                f"peers (1-2 SCADA masters, NTP, syslog, engineering workstation). "
                f"Excessive peers may indicate network scanning activity, a "
                f"compromised device being used as a pivot, or network misconfiguration."
            ),
            evidence={
                "peer_count": peer_count,
                "peers":      sorted(device.communicating_with)[:20],
            },
            remediation=(
                "Review and whitelist the authorised communication peers for this "
                "device. Implement firewall rules or device IP filtering to restrict "
                "connections to known-good addresses. Investigate unexpected peers."
            ),
            references=[
                "NERC CIP-005-6 R2 -- Electronic Security Perimeter",
                "IEC 62443-3-3 SR 5.1 -- Network Segmentation",
            ],
            first_seen=device.first_seen,
            packet_count=device.packet_count,
        ))
    return findings


# --------------------------------------------------- OPC-UA checks --------

def _check_opcua_no_security(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-OPCUA-001 -- OPC-UA with SecurityPolicy#None detected.
    OPC-UA supports multiple security policies. SecurityPolicy#None means
    no signing and no encryption -- all OPC-UA service calls (Read, Write,
    Call, Browse) are transmitted in cleartext without authentication of the
    message integrity, allowing eavesdropping and tampering.
    """
    findings = []
    proto_names = device.get_protocol_names()
    if "OPC-UA" not in proto_names:
        return findings

    # Look for SecurityPolicy#None in protocol detection details
    for proto in device.protocols:
        if proto.protocol != "OPC-UA":
            continue
        security_policy = proto.details.get("security_policy", "")
        security_mode = proto.details.get("security_mode", "")
        # Flag if SecurityPolicy is explicitly None, or if mode is None/unset
        if ("None" in security_policy or
                security_mode in ("None", "none", "") or
                not security_policy):
            findings.append(VulnerabilityFinding(
                vuln_id="OT-OPCUA-001",
                title="OPC-UA SecurityPolicy#None -- No Signing or Encryption",
                severity="high",
                category="encryption",
                description=(
                    f"OPC-UA server on {device.ip}:{proto.port} is operating with "
                    f"SecurityPolicy#None (security_policy='{security_policy}', "
                    f"security_mode='{security_mode}'). "
                    f"This means all OPC-UA service calls (Read, Write, Call, Browse, "
                    f"Subscribe) are transmitted without cryptographic signing or "
                    f"encryption. An attacker on the network can eavesdrop on process "
                    f"values, inject false writes to PLC tags, or invoke methods on "
                    f"OPC-UA server objects. OPC-UA SecurityPolicy#None is explicitly "
                    f"prohibited by IEC 62443-3-3 for SL-2 and above."
                ),
                evidence={
                    "device_ip":        device.ip,
                    "port":             proto.port,
                    "security_policy":  security_policy or "None (not set)",
                    "security_mode":    security_mode or "None (not set)",
                    "transport":        proto.transport,
                    "packet_count":     proto.packet_count,
                },
                remediation=(
                    "Configure the OPC-UA server to require at minimum "
                    "SecurityPolicy#Basic256Sha256 with MessageSecurityMode "
                    "SignAndEncrypt. Disable SecurityPolicy#None in the server "
                    "endpoint configuration. Deploy X.509 application instance "
                    "certificates for mutual authentication between OPC-UA clients "
                    "and servers. Refer to OPC 10000-4 (Services) and OPC 10000-7 "
                    "(Profiles) for security profile requirements."
                ),
                references=[
                    "OPC 10000-2:2022 -- OPC-UA Security Model",
                    "OPC 10000-4:2022 \u00a75.4 -- Security Policies",
                    "OPC 10000-7:2022 -- OPC-UA Profiles (Facet: Security)",
                    "IEC 62443-3-3 SR 4.3 -- Use of Cryptography",
                    "ICS-CERT Advisory ICSA-19-134 -- OPC-UA Implementations",
                ],
                first_seen=proto.first_seen,
                packet_count=proto.packet_count,
            ))
            break  # One finding per device is sufficient
    return findings


# --------------------------------------------------- MQTT checks ----------

def _check_mqtt_no_tls(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-MQTT-001 -- MQTT on port 1883 without TLS.
    Standard MQTT on TCP/1883 transmits all data (topics, payloads,
    credentials) in cleartext. MQTT over TLS uses port 8883.
    If MQTT traffic is observed on port 1883, TLS is not in use.
    """
    findings = []
    for proto in device.protocols:
        if proto.protocol != "MQTT":
            continue
        if proto.port == 1883:
            findings.append(VulnerabilityFinding(
                vuln_id="OT-MQTT-001",
                title="MQTT Without TLS (Cleartext on Port 1883)",
                severity="high",
                category="encryption",
                description=(
                    f"MQTT traffic on {device.ip}:1883 is transmitted in cleartext. "
                    f"All MQTT PUBLISH payloads (sensor data, actuator commands), "
                    f"SUBSCRIBE topic filters, and CONNECT credentials (username/"
                    f"password) are visible to any observer on the network path. "
                    f"OT/IIoT environments frequently use MQTT to transport process "
                    f"values and control commands between sensors, gateways, and "
                    f"SCADA/MES systems. Cleartext MQTT allows eavesdropping on "
                    f"operational data and injection of forged PUBLISH messages."
                ),
                evidence={
                    "device_ip":    device.ip,
                    "port":         1883,
                    "transport":    proto.transport,
                    "tls":          False,
                    "packet_count": proto.packet_count,
                },
                remediation=(
                    "Migrate MQTT communications to MQTT over TLS (port 8883). "
                    "Configure the MQTT broker to require TLS 1.2+ with mutual "
                    "certificate authentication (mTLS) for all clients. Disable "
                    "the plaintext listener on port 1883. If the broker or client "
                    "firmware does not support TLS, use an encrypted tunnel (e.g., "
                    "stunnel, IPsec VPN) between the MQTT client and broker."
                ),
                references=[
                    "OASIS MQTT Version 5.0 \u00a71.5 -- Security",
                    "OASIS MQTT Version 5.0 \u00a75.4.9 -- Enhanced Authentication",
                    "IEC 62443-3-3 SR 4.3 -- Use of Cryptography",
                    "NIST SP 800-183 -- Networks of 'Things' (IoT Security)",
                    "ENISA Good Practices for IoT Security -- Transport Encryption",
                ],
                first_seen=proto.first_seen,
                packet_count=proto.packet_count,
            ))
            break  # One finding per device
    return findings


def _check_mqtt_no_auth(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-MQTT-002 -- MQTT CONNECT without authentication (no username flag).
    MQTT CONNECT packets carry a Connect Flags byte. If the Username Flag
    (bit 7) is not set, the client is connecting without credentials,
    relying solely on network-level access control.
    """
    findings = []
    for proto in device.protocols:
        if proto.protocol != "MQTT":
            continue
        # Check if MQTT CONNECT was observed without username flag
        has_no_auth = proto.details.get("no_username_flag", False)
        anonymous_connects = proto.details.get("anonymous_connects", 0)
        if has_no_auth or anonymous_connects > 0:
            findings.append(VulnerabilityFinding(
                vuln_id="OT-MQTT-002",
                title="MQTT CONNECT Without Authentication (No Username Flag)",
                severity="high",
                category="authentication",
                description=(
                    f"MQTT client on {device.ip} sent CONNECT packet(s) to the "
                    f"broker without the Username Flag set in the Connect Flags byte. "
                    f"This means the client is connecting anonymously without "
                    f"presenting credentials. An unauthenticated MQTT client can "
                    f"subscribe to any topic (including OT control topics) and "
                    f"publish forged messages. In OT/IIoT environments this allows "
                    f"an attacker to read process data and inject false actuator "
                    f"commands via PUBLISH messages."
                ),
                evidence={
                    "device_ip":          device.ip,
                    "port":               proto.port,
                    "no_username_flag":   True,
                    "anonymous_connects": anonymous_connects,
                    "packet_count":       proto.packet_count,
                },
                remediation=(
                    "Configure the MQTT broker to require authentication for all "
                    "CONNECT requests. Use username/password authentication at minimum, "
                    "and preferably X.509 client certificate authentication (MQTT v5 "
                    "Enhanced Authentication). Disable anonymous access on the broker. "
                    "Implement MQTT topic-level ACLs to restrict which clients can "
                    "publish or subscribe to OT control topics."
                ),
                references=[
                    "OASIS MQTT Version 5.0 \u00a73.1.2.8 -- User Name Flag",
                    "OASIS MQTT Version 5.0 \u00a75.4.9 -- Enhanced Authentication",
                    "IEC 62443-3-3 SR 1.1 -- Human User Identification and Authentication",
                    "IEC 62443-3-3 SR 1.2 -- Software Process Identification",
                    "ENISA Good Practices for IoT Security -- Authentication",
                ],
                first_seen=proto.first_seen,
                packet_count=proto.packet_count,
            ))
            break  # One finding per device
    return findings


# ─────────────────────────────────────── IT/OT Convergence Checks ────

def _check_remote_access_in_ot(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-ITOT-001 — Remote access protocol (RDP, VNC, TeamViewer) detected on OT device.
    Remote access tools provide a direct path from IT/Internet into the OT zone.
    """
    findings = []
    remote_hits = [h for h in device.it_protocols if h.details.get("category") == "remote_access"
                   and h.protocol not in ("SSH",)]  # SSH is sometimes acceptable
    if remote_hits:
        protos = sorted(set(h.protocol for h in remote_hits))
        total_pkts = sum(h.packet_count for h in remote_hits)
        peers = sorted(set(h.src_ip if h.dst_ip == device.ip else h.dst_ip for h in remote_hits))
        findings.append(VulnerabilityFinding(
            vuln_id="OT-ITOT-001",
            title=f"Remote Access Protocol in OT Zone ({', '.join(protos)})",
            severity="high",
            category="convergence",
            description=(
                f"Device {device.ip} has remote access traffic: {', '.join(protos)}. "
                f"Remote desktop protocols provide a direct path for attackers to reach "
                f"OT devices. If an RDP/VNC session is compromised, the attacker gains "
                f"full control of the connected HMI or engineering workstation. "
                f"Peers: {', '.join(peers[:5])}"
            ),
            evidence={
                "protocols": protos,
                "total_packets": total_pkts,
                "remote_peers": peers[:10],
            },
            remediation=(
                "Remove direct RDP/VNC access to OT devices. Use a hardened jump server "
                "in the DMZ (Purdue Level 3.5) with MFA. Deploy an OT-approved remote "
                "access gateway with session recording. See IEC 62443-3-3 SR 1.13, "
                "NERC CIP-005-6 R2."
            ),
            references=[
                "IEC 62443-3-3 SR 1.13 — Remote Access Control",
                "NERC CIP-005-6 R2 — Interactive Remote Access",
                "NIST SP 800-82 Rev 3 §6.2.8 — Remote Access",
            ],
            packet_count=total_pkts,
        ))
    return findings


def _check_database_in_ot(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-ITOT-002 — Database protocol detected on OT device.
    Databases in OT zones often contain process data historians.
    Direct DB access from IT is a data exfiltration and injection risk.
    """
    findings = []
    db_hits = [h for h in device.it_protocols if h.details.get("category") == "database"]
    if db_hits:
        protos = sorted(set(h.protocol for h in db_hits))
        findings.append(VulnerabilityFinding(
            vuln_id="OT-ITOT-002",
            title=f"Database Protocol in OT Zone ({', '.join(protos)})",
            severity="medium",
            category="convergence",
            description=(
                f"Device {device.ip} has database traffic: {', '.join(protos)}. "
                f"Database services in OT zones may expose process historian data "
                f"or provide SQL injection paths into SCADA systems."
            ),
            evidence={"protocols": protos, "total_packets": sum(h.packet_count for h in db_hits)},
            remediation=(
                "Move database servers to Purdue Level 3 (site operations) behind a "
                "firewall. Use read-only replicas or OPC-UA data diodes for IT access. "
                "Never expose database ports directly to Level 0-1 devices."
            ),
            references=["IEC 62443-3-3 SR 5.1 — Network Segmentation"],
            packet_count=sum(h.packet_count for h in db_hits),
        ))
    return findings


def _check_telnet_in_ot(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-ITOT-003 — Telnet detected on OT device.
    Telnet sends credentials in cleartext. Common on legacy OT devices.
    """
    findings = []
    telnet_hits = [h for h in device.it_protocols if h.protocol == "Telnet"]
    if telnet_hits:
        total_pkts = sum(h.packet_count for h in telnet_hits)
        findings.append(VulnerabilityFinding(
            vuln_id="OT-ITOT-003",
            title="Telnet (Cleartext Remote Access) on OT Device",
            severity="critical",
            category="convergence",
            description=(
                f"Device {device.ip} has Telnet (TCP/23) traffic. Telnet transmits all "
                f"data including credentials in cleartext. An attacker on the network "
                f"can capture login credentials via passive sniffing."
            ),
            evidence={"total_packets": total_pkts},
            remediation=(
                "Replace Telnet with SSH. If the device does not support SSH, use a "
                "serial console server or encrypted tunnel. Disable Telnet service "
                "on all OT devices."
            ),
            references=[
                "IEC 62443-3-3 SR 4.3 — Use of Cryptography",
                "NERC CIP-007-6 R1 — Ports and Services",
            ],
            packet_count=total_pkts,
        ))
    return findings


def _check_file_sharing_in_ot(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-ITOT-004 — File sharing protocol (SMB/FTP/TFTP) on OT device.
    SMB is the #1 ransomware propagation vector.
    """
    findings = []
    fs_hits = [h for h in device.it_protocols if h.details.get("category") == "file_sharing"]
    if fs_hits:
        protos = sorted(set(h.protocol for h in fs_hits))
        total_pkts = sum(h.packet_count for h in fs_hits)
        sev = "critical" if "SMB" in protos else "high"
        findings.append(VulnerabilityFinding(
            vuln_id="OT-ITOT-004",
            title=f"File Sharing Protocol in OT Zone ({', '.join(protos)})",
            severity=sev,
            category="convergence",
            description=(
                f"Device {device.ip} has file sharing traffic: {', '.join(protos)}. "
                f"SMB is the primary propagation vector for ransomware (WannaCry, "
                f"NotPetya, EKANS). FTP/TFTP transmit files and credentials in cleartext."
            ),
            evidence={"protocols": protos, "total_packets": total_pkts},
            remediation=(
                "Block SMB (TCP/445) at OT zone boundaries. Use application whitelisting "
                "and a dedicated OT patch server for file transfers. Replace FTP with SFTP. "
                "See IEC 62443-3-3 SR 7.7 (Least Functionality)."
            ),
            references=[
                "IEC 62443-3-3 SR 7.7 — Least Functionality",
                "NERC CIP-007-6 R1 — Ports and Services",
                "ICS-CERT Alert TA17-132A — WannaCry/SMB",
            ],
            packet_count=total_pkts,
        ))
    return findings


def _check_high_it_protocol_count(device: OTDevice) -> List[VulnerabilityFinding]:
    """
    OT-ITOT-005 — Device running many IT protocols in OT zone.
    A device with 3+ IT protocols is likely an IT asset in the OT network
    or a compromised device performing reconnaissance.
    """
    findings = []
    if len(device.it_protocols) >= 3:
        protos = sorted(set(h.protocol for h in device.it_protocols))
        findings.append(VulnerabilityFinding(
            vuln_id="OT-ITOT-005",
            title=f"Excessive IT Protocol Activity on OT Device ({len(protos)} protocols)",
            severity="medium",
            category="convergence",
            description=(
                f"Device {device.ip} has {len(protos)} IT protocols active: "
                f"{', '.join(protos)}. OT devices should have minimal IT protocol exposure. "
                f"High IT protocol counts may indicate an IT asset misplaced in the OT zone, "
                f"or a compromised device performing network reconnaissance."
            ),
            evidence={"it_protocols": protos, "count": len(protos)},
            remediation=(
                "Verify whether this device belongs in the OT zone. If it's an IT asset, "
                "relocate it to the appropriate IT segment. If it's a legitimate OT device, "
                "disable unnecessary IT services and apply firewall rules to restrict "
                "IT protocol access."
            ),
            references=["IEC 62443-3-3 SR 7.7 — Least Functionality"],
            packet_count=sum(h.packet_count for h in device.it_protocols),
        ))
    return findings
