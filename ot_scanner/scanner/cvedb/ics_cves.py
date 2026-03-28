"""
Curated ICS/SCADA CVE database for the OT Passive Scanner.

Contains 80+ high-impact CVEs across all major OT vendors:
  Siemens, Rockwell Automation, Schneider Electric, ABB,
  GE / GE Grid Solutions, SEL (Schweitzer), Omron,
  Mitsubishi Electric, Honeywell, Yokogawa, and cross-vendor protocols.

Each entry maps to a CVEEntry dataclass and is matched against
discovered OTDevice instances by the CVEMatcher engine.
"""

from typing import Dict, List

# ──────────────────────────────────────────────────────────────────────
# ICS CVE DATABASE
# ──────────────────────────────────────────────────────────────────────

ICS_CVE_DATABASE: List[Dict] = [

    # ═══════════════════════════════════════════════════════════════════
    #  SIEMENS  (15 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2019-13945",
        "vendor": "Siemens",
        "product_pattern": r"S7-1200|S7-1500|S7-300|S7-400|SIMATIC\s*S7",
        "affected_versions": "<4.5",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Siemens S7-1200/S7-1500 Replay Attack",
        "description": (
            "Siemens S7-1200 and S7-1500 PLCs prior to firmware V4.5 are "
            "vulnerable to a replay attack that allows an unauthenticated "
            "attacker to gain full control of the PLC by replaying captured "
            "S7comm+ authentication packets."
        ),
        "has_public_exploit": True,
        "epss_score": 0.91,
        "is_cisa_kev": True,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-19-344-02",
        "remediation": "Update firmware to V4.5 or later. Enable S7comm+ encrypted communication.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-19-344-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-13945",
        ],
    },
    {
        "cve_id": "CVE-2020-15782",
        "vendor": "Siemens",
        "product_pattern": r"S7-1200|S7-1500|SIMATIC\s*S7",
        "affected_versions": "<2.9",
        "severity": "high",
        "cvss_score": 8.1,
        "title": "Siemens S7-1200/S7-1500 Memory Protection Bypass",
        "description": (
            "An attacker with network access to the PLC can bypass memory "
            "protection and write or read arbitrary data in protected memory "
            "areas, enabling code execution on the PLC."
        ),
        "has_public_exploit": False,
        "epss_score": 0.14,
        "is_cisa_kev": True,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-21-152-01",
        "remediation": "Update firmware to V2.9 or later. Restrict network access to PLCs.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-21-152-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-15782",
        ],
    },
    {
        "cve_id": "CVE-2019-6568",
        "vendor": "Siemens",
        "product_pattern": r"S7-1200|S7-1500|S7-300|S7-400|SIMATIC\s*S7|SIMATIC\s*CP",
        "affected_versions": "*",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "SIMATIC S7 Denial-of-Service via Crafted Packets",
        "description": (
            "Multiple SIMATIC S7 products are vulnerable to denial-of-service "
            "attacks caused by specially crafted network packets sent to the "
            "S7comm service port (TCP/102), causing the PLC to enter a defect state."
        ),
        "has_public_exploit": False,
        "epss_score": 0.11,
        "is_cisa_kev": True,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-19-099-02",
        "remediation": "Apply Siemens firmware updates. Use network segmentation to limit access to TCP/102.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-19-099-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-6568",
        ],
    },
    {
        "cve_id": "CVE-2022-38465",
        "vendor": "Siemens",
        "product_pattern": r"S7-1500|S7-1200|SIMATIC\s*S7",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Siemens S7-1500 Cryptographic Key Extraction",
        "description": (
            "The global private cryptographic key used to protect S7-1500 PLC "
            "firmware and encrypted communication can be extracted, allowing "
            "attackers to decrypt firmware, forge communication, and compromise "
            "any S7-1500 PLC."
        ),
        "has_public_exploit": True,
        "epss_score": 0.93,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-22-286-07",
        "remediation": (
            "Siemens has released new hardware revisions with individual keys. "
            "Upgrade to S7-1500 hardware version 3 and firmware V3.0 or later."
        ),
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-286-07",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-38465",
        ],
    },
    {
        "cve_id": "CVE-2023-44373",
        "vendor": "Siemens",
        "product_pattern": r"SCALANCE|RUGGEDCOM",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.1,
        "title": "SCALANCE/RUGGEDCOM Command Injection",
        "description": (
            "Siemens SCALANCE and RUGGEDCOM network devices contain an OS "
            "command injection vulnerability in the web management interface, "
            "allowing authenticated attackers to execute arbitrary commands "
            "with root privileges."
        ),
        "has_public_exploit": False,
        "epss_score": 0.28,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-23-320-08",
        "remediation": "Update to the latest firmware. Restrict web management access to trusted networks.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-320-08",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-44373",
        ],
    },
    {
        "cve_id": "CVE-2019-10929",
        "vendor": "Siemens",
        "product_pattern": r"S7-1200|S7-1500|S7-300|S7-400|SIMATIC\s*CP|SIMATIC\s*S7",
        "affected_versions": "*",
        "severity": "medium",
        "cvss_score": 5.9,
        "title": "SIMATIC S7 Communication Processor Man-in-the-Middle",
        "description": (
            "SIMATIC S7 communication processors insufficiently validate "
            "integrity of S7comm+ sessions, enabling a man-in-the-middle "
            "attacker to modify PLC program downloads and data exchange."
        ),
        "has_public_exploit": False,
        "epss_score": 0.04,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-19-344-04",
        "remediation": "Enable TLS-based communication and update to the latest firmware.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-19-344-04",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-10929",
        ],
    },
    {
        "cve_id": "CVE-2021-40358",
        "vendor": "Siemens",
        "product_pattern": r"S7-1200|S7-1500|SIMATIC\s*S7",
        "affected_versions": "<4.5",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "SIMATIC S7 Web Server Buffer Overflow",
        "description": (
            "A buffer overflow in the integrated web server of SIMATIC S7-1200 "
            "and S7-1500 PLCs allows an unauthenticated remote attacker to "
            "execute arbitrary code or crash the device."
        ),
        "has_public_exploit": False,
        "epss_score": 0.32,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-21-287-07",
        "remediation": "Update firmware to V4.5 or later. Disable the web server if not needed.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-21-287-07",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-40358",
        ],
    },
    {
        "cve_id": "CVE-2019-13090",
        "vendor": "Siemens",
        "product_pattern": r"SIPROTEC\s*5|SIPROTEC",
        "affected_versions": "<8.0",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "SIPROTEC 5 IEC 61850 MMS Denial-of-Service",
        "description": (
            "Siemens SIPROTEC 5 IED devices with IEC 61850 MMS enabled are "
            "vulnerable to denial-of-service by sending specially crafted MMS "
            "messages, causing the device to reboot."
        ),
        "has_public_exploit": False,
        "epss_score": 0.08,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-19-190-03",
        "remediation": "Update firmware to V8.0 or later. Restrict MMS port access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-19-190-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-13090",
        ],
    },
    {
        "cve_id": "CVE-2023-46284",
        "vendor": "Siemens",
        "product_pattern": r"SIMATIC|SIPLUS|S7-1500|S7-1200",
        "affected_versions": "*",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "SIMATIC/SIPLUS Improper Authentication",
        "description": (
            "SIMATIC and SIPLUS devices fail to properly validate "
            "authentication in certain API calls, allowing an unauthenticated "
            "attacker to read or modify PLC configuration."
        ),
        "has_public_exploit": False,
        "epss_score": 0.07,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-23-348-03",
        "remediation": "Apply Siemens security patches. Enable access protection on the PLC.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-348-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-46284",
        ],
    },
    {
        "cve_id": "CVE-2021-31338",
        "vendor": "Siemens",
        "product_pattern": r"TIA\s*Portal|STEP\s*7",
        "affected_versions": "<17.0",
        "severity": "high",
        "cvss_score": 7.8,
        "title": "TIA Portal Code Execution",
        "description": (
            "Siemens TIA Portal allows local attackers to execute arbitrary "
            "code by loading a malicious project file, potentially compromising "
            "the engineering workstation."
        ),
        "has_public_exploit": False,
        "epss_score": 0.12,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-21-194-10",
        "remediation": "Update TIA Portal to V17 or later. Do not open untrusted project files.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-21-194-10",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-31338",
        ],
    },
    {
        "cve_id": "CVE-2022-46350",
        "vendor": "Siemens",
        "product_pattern": r"SCALANCE\s*XM-400|SCALANCE\s*XR-500|SCALANCE\s*X",
        "affected_versions": "<6.5",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "SCALANCE XM-400 Web Vulnerability",
        "description": (
            "Siemens SCALANCE XM-400 and XR-500 industrial Ethernet switches "
            "contain a critical vulnerability in the web interface that allows "
            "unauthenticated remote code execution."
        ),
        "has_public_exploit": False,
        "epss_score": 0.24,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-22-349-04",
        "remediation": "Update firmware to V6.5 or later. Disable web interface if not required.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-349-04",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-46350",
        ],
    },
    {
        "cve_id": "CVE-2020-28397",
        "vendor": "Siemens",
        "product_pattern": r"S7-1200|S7-1500|S7-300|S7-400|SIMATIC\s*S7",
        "affected_versions": "*",
        "severity": "medium",
        "cvss_score": 5.3,
        "title": "SIMATIC S7 Hardcoded Cryptographic Keys",
        "description": (
            "SIMATIC S7 PLCs use hardcoded cryptographic keys for firmware "
            "encryption and integrity checks, allowing attackers who extract "
            "the key to decrypt or modify PLC firmware."
        ),
        "has_public_exploit": False,
        "epss_score": 0.06,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-20-252-02",
        "remediation": "Upgrade to hardware supporting individual device keys. Apply firmware updates.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-20-252-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-28397",
        ],
    },
    {
        "cve_id": "CVE-2024-38876",
        "vendor": "Siemens",
        "product_pattern": r"S7-1500|S7-1200|SIMATIC\s*S7",
        "affected_versions": "*",
        "severity": "high",
        "cvss_score": 8.8,
        "title": "SIMATIC S7 Authorization Bypass",
        "description": (
            "Siemens SIMATIC S7-1500 and S7-1200 PLCs contain an authorization "
            "bypass vulnerability that allows an authenticated low-privilege "
            "user to escalate privileges and modify the PLC program."
        ),
        "has_public_exploit": False,
        "epss_score": 0.09,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-24-193-06",
        "remediation": "Update to latest firmware. Enforce role-based access control on PLC projects.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-24-193-06",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-38876",
        ],
    },
    {
        "cve_id": "CVE-2023-49621",
        "vendor": "Siemens",
        "product_pattern": r"SINEC\s*INS",
        "affected_versions": "<1.0.1.1",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "SINEC INS Default Credentials",
        "description": (
            "Siemens SINEC INS (Infrastructure Network Services) ships with "
            "default administrative credentials that allow unauthenticated "
            "remote attackers to gain full control of the management platform."
        ),
        "has_public_exploit": True,
        "epss_score": 0.89,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-23-348-12",
        "remediation": "Update to V1.0.1.1 or later. Change all default credentials immediately.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-348-12",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-49621",
        ],
    },
    {
        "cve_id": "CVE-2024-46886",
        "vendor": "Siemens",
        "product_pattern": r"SINEMA\s*Remote\s*Connect",
        "affected_versions": "<3.2",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "SINEMA Remote Connect Privilege Escalation",
        "description": (
            "Siemens SINEMA Remote Connect server allows remote attackers "
            "to escalate privileges to administrative level, potentially "
            "compromising all remotely managed OT devices."
        ),
        "has_public_exploit": False,
        "epss_score": 0.37,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-24-284-05",
        "remediation": "Update to V3.2 or later. Restrict remote access to trusted networks.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-24-284-05",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-46886",
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    #  ROCKWELL AUTOMATION  (10 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2022-1159",
        "vendor": "Rockwell Automation",
        "product_pattern": r"ControlLogix|CompactLogix|1756|1769",
        "affected_versions": "<33.0",
        "severity": "high",
        "cvss_score": 7.7,
        "title": "ControlLogix/CompactLogix Firmware Update Vulnerability",
        "description": (
            "Rockwell Automation ControlLogix and CompactLogix controllers "
            "allow an attacker with access to the engineering workstation to "
            "modify PLC firmware during the update process, injecting malicious "
            "code that persists across reboots."
        ),
        "has_public_exploit": False,
        "epss_score": 0.10,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-22-090-05",
        "remediation": "Update to firmware V33.0 or later. Use CIP Security for firmware transfers.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-090-05",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-1159",
        ],
    },
    {
        "cve_id": "CVE-2023-3595",
        "vendor": "Rockwell Automation",
        "product_pattern": r"ControlLogix|1756-EN2|1756-EN3|1756-EN4",
        "affected_versions": "<33.017",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "ControlLogix Remote Code Execution (PIPEDREAM/CHERNOVITE)",
        "description": (
            "Critical RCE vulnerability in ControlLogix EtherNet/IP communication "
            "modules exploitable by state-sponsored threat actors (CHERNOVITE/PIPEDREAM). "
            "Allows unauthenticated remote code execution and full device compromise."
        ),
        "has_public_exploit": True,
        "epss_score": 0.97,
        "is_cisa_kev": True,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-23-193-01",
        "remediation": "Apply firmware V33.017 or later immediately. Segment CIP communications.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-193-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-3595",
        ],
    },
    {
        "cve_id": "CVE-2023-3596",
        "vendor": "Rockwell Automation",
        "product_pattern": r"ControlLogix|1756-EN2|1756-EN3|1756-EN4",
        "affected_versions": "<11.004",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "ControlLogix 1756 Denial-of-Service",
        "description": (
            "Rockwell Automation ControlLogix 1756 EtherNet/IP modules are "
            "vulnerable to denial-of-service via specially crafted CIP packets, "
            "causing the communication module to become unresponsive."
        ),
        "has_public_exploit": False,
        "epss_score": 0.13,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-23-193-02",
        "remediation": "Update to firmware V11.004 or later. Implement CIP deep-packet inspection.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-193-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-3596",
        ],
    },
    {
        "cve_id": "CVE-2012-6435",
        "vendor": "Rockwell Automation",
        "product_pattern": r"MicroLogix\s*1100|1763",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "MicroLogix 1100 Hardcoded Credentials",
        "description": (
            "Rockwell Automation MicroLogix 1100 controllers contain hardcoded "
            "credentials that allow unauthenticated remote access to the web "
            "server and full device configuration."
        ),
        "has_public_exploit": True,
        "epss_score": 0.95,
        "is_cisa_kev": True,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-13-011-03",
        "remediation": "Replace MicroLogix 1100 with newer hardware. Restrict network access to the controller.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-13-011-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2012-6435",
        ],
    },
    {
        "cve_id": "CVE-2022-3157",
        "vendor": "Rockwell Automation",
        "product_pattern": r"CompactLogix|1769|Compact\s*GuardLogix",
        "affected_versions": "<34.0",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "CompactLogix Denial-of-Service via CIP",
        "description": (
            "Rockwell Automation CompactLogix controllers are vulnerable to "
            "denial-of-service via specially crafted CIP messages, causing "
            "the controller to fault and require a manual restart."
        ),
        "has_public_exploit": False,
        "epss_score": 0.06,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-22-300-03",
        "remediation": "Update to firmware V34.0 or later. Use CIP Security to restrict access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-300-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-3157",
        ],
    },
    {
        "cve_id": "CVE-2020-6111",
        "vendor": "Rockwell Automation",
        "product_pattern": r"MicroLogix\s*1100|1763",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "MicroLogix 1100 EtherNet/IP Buffer Overflow",
        "description": (
            "A stack-based buffer overflow in the EtherNet/IP handler of "
            "MicroLogix 1100 allows an unauthenticated remote attacker to "
            "execute arbitrary code or crash the controller."
        ),
        "has_public_exploit": True,
        "epss_score": 0.87,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-20-070-06",
        "remediation": "Migrate to newer controller hardware. Restrict EtherNet/IP access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-20-070-06",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-6111",
        ],
    },
    {
        "cve_id": "CVE-2023-46290",
        "vendor": "Rockwell Automation",
        "product_pattern": r"FactoryTalk|FT\s*Services",
        "affected_versions": "<6.40",
        "severity": "high",
        "cvss_score": 8.1,
        "title": "FactoryTalk Services Authentication Bypass",
        "description": (
            "Rockwell Automation FactoryTalk Services Platform contains an "
            "authentication bypass that allows remote attackers to gain "
            "unauthorized access to engineering and SCADA services."
        ),
        "has_public_exploit": False,
        "epss_score": 0.16,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-23-306-01",
        "remediation": "Update FactoryTalk Services to V6.40 or later.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-306-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-46290",
        ],
    },
    {
        "cve_id": "CVE-2024-6242",
        "vendor": "Rockwell Automation",
        "product_pattern": r"ControlLogix|1756|GuardLogix",
        "affected_versions": "<34.011",
        "severity": "high",
        "cvss_score": 8.4,
        "title": "ControlLogix Trusted Slot Bypass",
        "description": (
            "Rockwell Automation ControlLogix controllers contain a trusted "
            "slot bypass vulnerability that allows an attacker to send CIP "
            "commands to the PLC backplane from an untrusted slot."
        ),
        "has_public_exploit": True,
        "epss_score": 0.74,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-24-193-17",
        "remediation": "Apply firmware V34.011 or later. Verify trusted slot configuration.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-24-193-17",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6242",
        ],
    },
    {
        "cve_id": "CVE-2022-1161",
        "vendor": "Rockwell Automation",
        "product_pattern": r"ControlLogix|CompactLogix|1756|1769|GuardLogix",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 10.0,
        "title": "ControlLogix PLC Program Modification (Stuxnet-style)",
        "description": (
            "An attacker with network access to a ControlLogix or CompactLogix "
            "PLC can modify the running program while presenting a different "
            "version to the engineering workstation, a Stuxnet-style attack."
        ),
        "has_public_exploit": True,
        "epss_score": 0.96,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-22-090-07",
        "remediation": "Update to latest firmware. Use CIP Security and program change detection.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-090-07",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-1161",
        ],
    },
    {
        "cve_id": "CVE-2024-21914",
        "vendor": "Rockwell Automation",
        "product_pattern": r"Micro800|Micro810|Micro820|Micro830|Micro850|Micro870|Micro880|2080",
        "affected_versions": "*",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "Micro800 Denial-of-Service via EtherNet/IP",
        "description": (
            "Rockwell Automation Micro800 series controllers are vulnerable "
            "to denial-of-service via crafted EtherNet/IP packets that cause "
            "the controller to stop executing its control program."
        ),
        "has_public_exploit": False,
        "epss_score": 0.05,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-24-046-02",
        "remediation": "Apply latest firmware update. Restrict EtherNet/IP traffic to trusted hosts.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-24-046-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-21914",
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    #  SCHNEIDER ELECTRIC  (10 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2021-22779",
        "vendor": "Schneider Electric",
        "product_pattern": r"Modicon\s*M340|Modicon\s*M580|BMXP|BMEP",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Modicon M340/M580 Authentication Bypass",
        "description": (
            "Schneider Electric Modicon M340 and M580 PLCs contain an "
            "authentication bypass vulnerability allowing unauthenticated "
            "attackers to gain full control of the PLC via Modbus/TCP."
        ),
        "has_public_exploit": True,
        "epss_score": 0.94,
        "is_cisa_kev": True,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-21-232-04",
        "remediation": "Apply firmware updates. Enable application password protection on PLCs.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-21-232-04",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22779",
        ],
    },
    {
        "cve_id": "CVE-2022-45788",
        "vendor": "Schneider Electric",
        "product_pattern": r"Modicon\s*M340|Modicon\s*M580|Modicon\s*MC80|BMXP|BMEP",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Modicon PLC Remote Code Execution",
        "description": (
            "Schneider Electric Modicon PLCs are vulnerable to remote code "
            "execution via crafted Modbus/TCP requests, allowing full "
            "compromise of the PLC and connected process control."
        ),
        "has_public_exploit": True,
        "epss_score": 0.92,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-23-040-04",
        "remediation": "Apply latest firmware patches. Restrict Modbus/TCP access to authorized hosts.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-040-04",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-45788",
        ],
    },
    {
        "cve_id": "CVE-2020-7559",
        "vendor": "Schneider Electric",
        "product_pattern": r"Modicon\s*M340|BMXNOE|BMXNOR",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Modicon M340 FTP Hardcoded Credentials",
        "description": (
            "The FTP service on Schneider Electric Modicon M340 communication "
            "modules uses hardcoded credentials, allowing unauthenticated "
            "attackers to access and modify PLC files."
        ),
        "has_public_exploit": False,
        "epss_score": 0.21,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-20-205-01",
        "remediation": "Disable FTP if not required. Apply firmware updates. Restrict network access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-20-205-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7559",
        ],
    },
    {
        "cve_id": "CVE-2018-7760",
        "vendor": "Schneider Electric",
        "product_pattern": r"Modicon\s*M340|BMXNOE|BMXP",
        "affected_versions": "<3.10",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Modicon M340 Web Server Authentication Bypass",
        "description": (
            "The web server on Schneider Electric Modicon M340 PLCs contains "
            "an authentication bypass that allows unauthenticated remote "
            "attackers to access diagnostic pages and modify settings."
        ),
        "has_public_exploit": False,
        "epss_score": 0.35,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-18-065-01",
        "remediation": "Update firmware to V3.10 or later. Disable the web server if not needed.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-18-065-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-7760",
        ],
    },
    {
        "cve_id": "CVE-2019-6857",
        "vendor": "Schneider Electric",
        "product_pattern": r"Modicon\s*M580|BMEP",
        "affected_versions": "<3.20",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "Modicon M580 Denial-of-Service",
        "description": (
            "Schneider Electric Modicon M580 PLCs are vulnerable to "
            "denial-of-service via crafted Modbus/TCP packets that cause "
            "the PLC to enter a fault state requiring a manual restart."
        ),
        "has_public_exploit": False,
        "epss_score": 0.09,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-19-183-01",
        "remediation": "Update firmware to V3.20 or later. Implement Modbus/TCP filtering.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-19-183-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-6857",
        ],
    },
    {
        "cve_id": "CVE-2023-5391",
        "vendor": "Schneider Electric",
        "product_pattern": r"EcoStruxure|Modicon\s*M340|Modicon\s*M580|BMXP|BMEP",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "EcoStruxure/Modicon Command Injection",
        "description": (
            "Schneider Electric EcoStruxure Control Expert and Modicon PLCs "
            "are vulnerable to command injection via specially crafted project "
            "files, allowing arbitrary code execution on the engineering "
            "workstation or PLC."
        ),
        "has_public_exploit": False,
        "epss_score": 0.19,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-23-320-01",
        "remediation": "Apply vendor patches. Validate project file integrity before loading.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-320-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-5391",
        ],
    },
    {
        "cve_id": "CVE-2021-22786",
        "vendor": "Schneider Electric",
        "product_pattern": r"Modicon\s*M340|Modicon\s*M580|BMXP|BMEP",
        "affected_versions": "*",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "Modicon Information Disclosure",
        "description": (
            "Schneider Electric Modicon PLCs expose sensitive information "
            "including project structure and memory contents to unauthenticated "
            "attackers via Modbus/TCP function code reads."
        ),
        "has_public_exploit": False,
        "epss_score": 0.07,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-21-334-03",
        "remediation": "Apply firmware updates. Restrict Modbus/TCP access to trusted SCADA hosts.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-21-334-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22786",
        ],
    },
    {
        "cve_id": "CVE-2024-8306",
        "vendor": "Schneider Electric",
        "product_pattern": r"Easergy\s*T300|Easergy",
        "affected_versions": "<2.10",
        "severity": "high",
        "cvss_score": 8.8,
        "title": "Easergy T300 Remote Code Execution",
        "description": (
            "Schneider Electric Easergy T300 RTUs contain a vulnerability "
            "that allows authenticated attackers to execute arbitrary code "
            "on the device, compromising substation automation systems."
        ),
        "has_public_exploit": False,
        "epss_score": 0.18,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-24-226-01",
        "remediation": "Update firmware to V2.10 or later. Restrict remote access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-24-226-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-8306",
        ],
    },
    {
        "cve_id": "CVE-2022-34764",
        "vendor": "Schneider Electric",
        "product_pattern": r"IGSS|Interactive\s*Graphical\s*SCADA",
        "affected_versions": "<16.0",
        "severity": "high",
        "cvss_score": 7.8,
        "title": "IGSS SCADA Code Execution",
        "description": (
            "Schneider Electric IGSS SCADA software allows code execution "
            "when a user opens a malicious project file, potentially "
            "compromising the SCADA server."
        ),
        "has_public_exploit": True,
        "epss_score": 0.68,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-22-195-02",
        "remediation": "Update IGSS to V16.0 or later. Do not open untrusted project files.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-195-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-34764",
        ],
    },
    {
        "cve_id": "CVE-2020-7540",
        "vendor": "Schneider Electric",
        "product_pattern": r"SCADAPack|SCADAPack\s*RTU",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "SCADAPack RTU Authentication Bypass",
        "description": (
            "Schneider Electric SCADAPack RTUs contain an authentication "
            "bypass vulnerability that allows remote unauthenticated "
            "attackers to access and modify the RTU configuration."
        ),
        "has_public_exploit": False,
        "epss_score": 0.26,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-20-282-02",
        "remediation": "Apply vendor firmware updates. Enable authentication on all RTU interfaces.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-20-282-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7540",
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    #  ABB  (8 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2023-0228",
        "vendor": "ABB",
        "product_pattern": r"ASPECT|ASPECT-Enterprise|NEXUS|MATRIX",
        "affected_versions": "<3.08",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "ABB ASPECT System Hardcoded Credentials",
        "description": (
            "ABB ASPECT building energy management systems contain hardcoded "
            "default credentials that allow unauthenticated remote attackers "
            "to gain administrative access to the system."
        ),
        "has_public_exploit": False,
        "epss_score": 0.33,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-23-033-01",
        "remediation": "Update to V3.08 or later. Change all default credentials immediately.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-033-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-0228",
        ],
    },
    {
        "cve_id": "CVE-2022-31216",
        "vendor": "ABB",
        "product_pattern": r"RTU560|RTU500",
        "affected_versions": "<12.4",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "ABB RTU560 Default Credentials",
        "description": (
            "ABB RTU560 remote terminal units ship with default credentials "
            "that allow unauthenticated remote attackers to access the RTU "
            "configuration interface and modify operational parameters."
        ),
        "has_public_exploit": False,
        "epss_score": 0.29,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-22-235-03",
        "remediation": "Update firmware to V12.4 or later. Change all default credentials.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-235-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-31216",
        ],
    },
    {
        "cve_id": "CVE-2020-8479",
        "vendor": "ABB",
        "product_pattern": r"System\s*800xA|800xA|Ability\s*Symphony",
        "affected_versions": "<6.1",
        "severity": "high",
        "cvss_score": 8.8,
        "title": "ABB System 800xA Code Execution",
        "description": (
            "ABB System 800xA DCS contains a vulnerability that allows an "
            "authenticated attacker on the control system network to execute "
            "arbitrary code on the DCS server or operator stations."
        ),
        "has_public_exploit": False,
        "epss_score": 0.15,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-20-154-04",
        "remediation": "Update to System 800xA V6.1 or later. Restrict network access to DCS components.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-20-154-04",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8479",
        ],
    },
    {
        "cve_id": "CVE-2023-6516",
        "vendor": "ABB",
        "product_pattern": r"REF615|RED615|REF61|RED61|Relion\s*615",
        "affected_versions": "<8.0",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "ABB REF615/RED615 IED Denial-of-Service",
        "description": (
            "ABB REF615 and RED615 intelligent electronic devices (IEDs) are "
            "vulnerable to denial-of-service via malformed IEC 61850 MMS "
            "messages, causing the relay to become unresponsive."
        ),
        "has_public_exploit": False,
        "epss_score": 0.08,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-23-348-01",
        "remediation": "Update firmware to V8.0 or later. Restrict MMS port access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-348-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-6516",
        ],
    },
    {
        "cve_id": "CVE-2022-29154",
        "vendor": "ABB",
        "product_pattern": r"PCM600",
        "affected_versions": "<2.12",
        "severity": "high",
        "cvss_score": 8.8,
        "title": "ABB PCM600 Engineering Tool RCE",
        "description": (
            "ABB PCM600 protection and control IED manager allows remote code "
            "execution when a user opens a crafted project file, potentially "
            "compromising the engineering workstation and connected IEDs."
        ),
        "has_public_exploit": False,
        "epss_score": 0.11,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-22-221-01",
        "remediation": "Update to PCM600 V2.12 or later. Validate project file sources.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-221-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-29154",
        ],
    },
    {
        "cve_id": "CVE-2019-18253",
        "vendor": "ABB",
        "product_pattern": r"Relion\s*670|REL670|Relion",
        "affected_versions": "<2.2",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "ABB Relion 670 IEC 61850 Denial-of-Service",
        "description": (
            "ABB Relion 670 series protection relays are vulnerable to "
            "denial-of-service via malformed IEC 61850 GOOSE or MMS messages, "
            "causing the relay to reboot during a power system event."
        ),
        "has_public_exploit": False,
        "epss_score": 0.06,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-19-330-01",
        "remediation": "Update firmware to V2.2 or later. Enable VLAN segmentation for GOOSE traffic.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-19-330-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-18253",
        ],
    },
    {
        "cve_id": "CVE-2024-0335",
        "vendor": "ABB",
        "product_pattern": r"REX640|REX6",
        "affected_versions": "<1.5",
        "severity": "high",
        "cvss_score": 8.6,
        "title": "ABB REX640 IED Authentication Bypass",
        "description": (
            "ABB REX640 intelligent electronic devices contain an "
            "authentication bypass vulnerability allowing unauthenticated "
            "remote attackers to modify protection relay settings."
        ),
        "has_public_exploit": False,
        "epss_score": 0.17,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-24-030-01",
        "remediation": "Update firmware to V1.5 or later. Enable role-based access control.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-24-030-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0335",
        ],
    },
    {
        "cve_id": "CVE-2021-22285",
        "vendor": "ABB",
        "product_pattern": r"RTU500|RTU560|RTU520",
        "affected_versions": "<12.7",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "ABB RTU500 Series Denial-of-Service",
        "description": (
            "ABB RTU500 series remote terminal units are vulnerable to "
            "denial-of-service via crafted IEC 60870-5-104 packets, causing "
            "the RTU to restart and lose SCADA connectivity."
        ),
        "has_public_exploit": False,
        "epss_score": 0.05,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-21-075-01",
        "remediation": "Update firmware to V12.7 or later. Implement IEC-104 traffic filtering.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-21-075-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22285",
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    #  GE / GE GRID SOLUTIONS  (6 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2022-37017",
        "vendor": "GE",
        "product_pattern": r"MiCOM|Alstom\s*MiCOM|GE\s*MiCOM",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "GE MiCOM Relay Authentication Bypass",
        "description": (
            "GE MiCOM protection relays contain an authentication bypass "
            "that allows unauthenticated remote attackers to access and "
            "modify relay settings, potentially disabling power system "
            "protection during a fault."
        ),
        "has_public_exploit": False,
        "epss_score": 0.22,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-22-319-01",
        "remediation": "Apply vendor firmware patches. Restrict relay network access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-319-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-37017",
        ],
    },
    {
        "cve_id": "CVE-2018-10936",
        "vendor": "GE",
        "product_pattern": r"MDS\s*Series|MDS\s*Orbit|MDS\s*SD|GE\s*MDS",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "GE MDS Series RTU Hardcoded Credentials",
        "description": (
            "GE MDS Series industrial radios and RTUs contain hardcoded "
            "credentials that allow remote unauthenticated attackers to "
            "access the device configuration and intercept SCADA communications."
        ),
        "has_public_exploit": True,
        "epss_score": 0.90,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-18-270-02",
        "remediation": "Apply firmware updates. Change default credentials. Restrict management access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-18-270-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-10936",
        ],
    },
    {
        "cve_id": "CVE-2021-27450",
        "vendor": "GE",
        "product_pattern": r"UR\s*family|UR\s*relay|G30|G60|L60|L90|C60|C90|B30|B90|F35|F60|N60|T35|T60|D30|D60",
        "affected_versions": "<8.10",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "GE UR Family Relay Remote Code Execution",
        "description": (
            "GE Universal Relay (UR) family protection relays are vulnerable "
            "to remote code execution via specially crafted network packets, "
            "allowing full compromise of the relay."
        ),
        "has_public_exploit": False,
        "epss_score": 0.38,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-21-075-02",
        "remediation": "Update firmware to V8.10 or later. Segment relay management networks.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-21-075-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-27450",
        ],
    },
    {
        "cve_id": "CVE-2020-16242",
        "vendor": "GE",
        "product_pattern": r"Multilin|GE\s*Multilin|750|760|SR",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "GE Multilin Firmware Upload Vulnerability",
        "description": (
            "GE Multilin protection relays allow unauthenticated firmware "
            "uploads, enabling attackers to replace the relay firmware with "
            "malicious versions that compromise protective functions."
        ),
        "has_public_exploit": False,
        "epss_score": 0.25,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-20-224-04",
        "remediation": "Apply firmware updates. Enable firmware signing verification. Restrict network access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-20-224-04",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-16242",
        ],
    },
    {
        "cve_id": "CVE-2019-6564",
        "vendor": "GE",
        "product_pattern": r"GE\s*Communicator|Communicator",
        "affected_versions": "<4.0.517",
        "severity": "high",
        "cvss_score": 8.8,
        "title": "GE Communicator Remote Code Execution",
        "description": (
            "GE Communicator software, used to configure GE protective relays, "
            "contains a remote code execution vulnerability that allows "
            "attackers to compromise the engineering workstation."
        ),
        "has_public_exploit": False,
        "epss_score": 0.12,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-19-134-01",
        "remediation": "Update to V4.0.517 or later. Restrict network access to engineering stations.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-19-134-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-6564",
        ],
    },
    {
        "cve_id": "CVE-2022-43975",
        "vendor": "GE",
        "product_pattern": r"D20MX|D200|D20|GE\s*D20",
        "affected_versions": "*",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "GE D20MX/D200 RTU Vulnerability",
        "description": (
            "GE D20MX and D200 remote terminal units contain a vulnerability "
            "that allows remote attackers to disrupt RTU operation and "
            "SCADA communications via crafted network packets."
        ),
        "has_public_exploit": False,
        "epss_score": 0.07,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-22-326-01",
        "remediation": "Apply firmware updates from GE Grid Solutions. Restrict network access to the RTU.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-326-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-43975",
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    #  SEL (SCHWEITZER ENGINEERING LABORATORIES)  (5 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2023-31168",
        "vendor": "SEL",
        "product_pattern": r"SEL-5030|acSELerator\s*QuickSet|acSELerator",
        "affected_versions": "<7.1",
        "severity": "high",
        "cvss_score": 8.8,
        "title": "SEL-5030 acSELerator QuickSet RCE",
        "description": (
            "Schweitzer Engineering Laboratories SEL-5030 acSELerator QuickSet "
            "software is vulnerable to remote code execution via crafted "
            "project files, compromising the engineering workstation."
        ),
        "has_public_exploit": False,
        "epss_score": 0.14,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-23-241-01",
        "remediation": "Update to SEL-5030 V7.1 or later. Validate project file sources.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-241-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-31168",
        ],
    },
    {
        "cve_id": "CVE-2023-34388",
        "vendor": "SEL",
        "product_pattern": r"SEL-3505|RTAC|SEL-35",
        "affected_versions": "<R150",
        "severity": "high",
        "cvss_score": 8.8,
        "title": "SEL-3505 RTAC Authentication Bypass",
        "description": (
            "Schweitzer Engineering Laboratories SEL-3505 Real-Time Automation "
            "Controller (RTAC) contains an authentication bypass that allows "
            "unauthenticated attackers to access configuration and control functions."
        ),
        "has_public_exploit": True,
        "epss_score": 0.71,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-23-241-02",
        "remediation": "Update to RTAC firmware R150 or later. Restrict network access to RTAC.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-241-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-34388",
        ],
    },
    {
        "cve_id": "CVE-2022-4103",
        "vendor": "SEL",
        "product_pattern": r"SEL-3530|RTAC|SEL-35",
        "affected_versions": "<R149",
        "severity": "medium",
        "cvss_score": 5.3,
        "title": "SEL-3530 RTAC Information Disclosure",
        "description": (
            "SEL-3530 RTAC devices expose sensitive configuration information "
            "to unauthenticated network requests, revealing device details "
            "useful for further attacks."
        ),
        "has_public_exploit": False,
        "epss_score": 0.03,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-22-349-01",
        "remediation": "Update to firmware R149 or later. Restrict RTAC management access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-349-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-4103",
        ],
    },
    {
        "cve_id": "CVE-2023-34390",
        "vendor": "SEL",
        "product_pattern": r"SEL-5033|acSELerator\s*Team|acSELerator",
        "affected_versions": "<3.1",
        "severity": "high",
        "cvss_score": 8.8,
        "title": "SEL-5033 acSELerator Code Execution",
        "description": (
            "Schweitzer Engineering Laboratories SEL-5033 acSELerator TEAM "
            "software allows code execution via malicious project files, "
            "potentially compromising the engineering environment."
        ),
        "has_public_exploit": False,
        "epss_score": 0.10,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-23-241-03",
        "remediation": "Update to SEL-5033 V3.1 or later. Only open trusted project files.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-241-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-34390",
        ],
    },
    {
        "cve_id": "CVE-2018-10600",
        "vendor": "SEL",
        "product_pattern": r"SEL-2241|RTAC\s*Module|SEL-22",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "SEL-2241 RTAC Module Authentication Bypass",
        "description": (
            "Schweitzer Engineering Laboratories SEL-2241 RTAC module contains "
            "an authentication bypass that allows remote unauthenticated "
            "attackers to access and reconfigure the device."
        ),
        "has_public_exploit": False,
        "epss_score": 0.40,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-18-191-02",
        "remediation": "Apply firmware updates. Restrict management access to trusted hosts.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-18-191-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-10600",
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    #  OMRON  (5 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2022-45790",
        "vendor": "Omron",
        "product_pattern": r"CJ\d|CS\d|CJ1|CJ2|CS1|FINS",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.1,
        "title": "Omron CJ/CS FINS Authentication Bypass",
        "description": (
            "Omron CJ and CS series PLCs using the FINS protocol lack proper "
            "authentication, allowing remote attackers to read/write PLC "
            "memory and modify the control program without credentials."
        ),
        "has_public_exploit": True,
        "epss_score": 0.86,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-22-314-01",
        "remediation": "Use FINS/TCP with IP filtering. Segment FINS traffic from untrusted networks.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-314-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-45790",
        ],
    },
    {
        "cve_id": "CVE-2022-34151",
        "vendor": "Omron",
        "product_pattern": r"NJ\d|NX\d|NJ501|NX102|NJ101",
        "affected_versions": "<1.49",
        "severity": "critical",
        "cvss_score": 9.4,
        "title": "Omron NJ/NX Hardcoded Credentials",
        "description": (
            "Omron NJ and NX series controllers contain hardcoded credentials "
            "that allow unauthenticated remote attackers to access the PLC "
            "and modify the running control program."
        ),
        "has_public_exploit": True,
        "epss_score": 0.88,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-22-179-01",
        "remediation": "Update firmware to V1.49 or later. Restrict network access to the controller.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-179-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-34151",
        ],
    },
    {
        "cve_id": "CVE-2023-0811",
        "vendor": "Omron",
        "product_pattern": r"CP1L|CJ2M|CP1E|CP1H|Omron\s*CP|Omron\s*CJ",
        "affected_versions": "*",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "Omron CP1L/CJ2M Denial-of-Service",
        "description": (
            "Omron CP1L and CJ2M PLCs are vulnerable to denial-of-service "
            "via malformed FINS packets, causing the PLC to stop executing "
            "its control program."
        ),
        "has_public_exploit": False,
        "epss_score": 0.08,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-23-073-01",
        "remediation": "Apply firmware updates. Implement FINS protocol filtering at network boundaries.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-073-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-0811",
        ],
    },
    {
        "cve_id": "CVE-2019-18261",
        "vendor": "Omron",
        "product_pattern": r"CJ\d|CS\d|CP\d|NJ\d|NX\d|FINS|Omron\s*PLC",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Omron PLC FINS Command Injection",
        "description": (
            "Omron PLCs using the FINS protocol are vulnerable to command "
            "injection via specially crafted FINS messages, allowing remote "
            "attackers to execute arbitrary commands on the PLC."
        ),
        "has_public_exploit": False,
        "epss_score": 0.31,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-19-346-02",
        "remediation": "Restrict FINS port access. Deploy application-layer firewalls for FINS traffic.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-19-346-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-18261",
        ],
    },
    {
        "cve_id": "CVE-2022-33208",
        "vendor": "Omron",
        "product_pattern": r"CX-Programmer|CX-One|CX-Server",
        "affected_versions": "<9.78",
        "severity": "high",
        "cvss_score": 7.8,
        "title": "Omron CX-Programmer Code Execution",
        "description": (
            "Omron CX-Programmer engineering software allows code execution "
            "when a user opens a malicious project file, compromising the "
            "engineering workstation used to program Omron PLCs."
        ),
        "has_public_exploit": False,
        "epss_score": 0.13,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-22-179-02",
        "remediation": "Update CX-Programmer to V9.78 or later. Do not open untrusted project files.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-179-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-33208",
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    #  MITSUBISHI ELECTRIC  (5 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2022-25164",
        "vendor": "Mitsubishi Electric",
        "product_pattern": r"MELSEC\s*iQ-R|MELSEC\s*FX5|iQ-R|FX5U|FX5UC|FX5UJ|R00|R01|R02|R04|R08|R16|R32|R120",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.1,
        "title": "MELSEC iQ-R/FX5 Authentication Bypass",
        "description": (
            "Mitsubishi Electric MELSEC iQ-R and FX5 series PLCs contain "
            "an authentication bypass that allows remote attackers to access "
            "the PLC without valid credentials via the MELSEC protocol."
        ),
        "has_public_exploit": False,
        "epss_score": 0.27,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-22-202-04",
        "remediation": "Apply vendor patches. Enable IP filtering on PLC communication modules.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-202-04",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-25164",
        ],
    },
    {
        "cve_id": "CVE-2023-6942",
        "vendor": "Mitsubishi Electric",
        "product_pattern": r"MELSEC-Q|MELSEC-L|MELSEC\s*iQ-R|Q\d{2,}|L\d{2,}|iQ-R",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "MELSEC-Q/L/iQ-R CPU Authentication Bypass",
        "description": (
            "Mitsubishi Electric MELSEC-Q, MELSEC-L, and iQ-R series CPU "
            "modules contain an authentication bypass that allows remote "
            "unauthenticated attackers to gain full control of the PLC."
        ),
        "has_public_exploit": True,
        "epss_score": 0.85,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-24-016-01",
        "remediation": "Apply vendor firmware updates. Enable IP filter and password protection.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-24-016-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-6942",
        ],
    },
    {
        "cve_id": "CVE-2020-5653",
        "vendor": "Mitsubishi Electric",
        "product_pattern": r"MELSEC\s*iQ-R|iQ-R|R00|R01|R02|R04|R08|R16|R32|R120",
        "affected_versions": "<49.0",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "MELSEC iQ-R Denial-of-Service via MELSEC-MC Protocol",
        "description": (
            "Mitsubishi Electric MELSEC iQ-R series PLCs are vulnerable to "
            "denial-of-service via crafted MELSEC-MC protocol packets, causing "
            "the CPU module to stop operation."
        ),
        "has_public_exploit": False,
        "epss_score": 0.06,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-20-282-01",
        "remediation": "Update firmware to V49.0 or later. Filter MELSEC-MC traffic at network boundaries.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-20-282-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-5653",
        ],
    },
    {
        "cve_id": "CVE-2021-20594",
        "vendor": "Mitsubishi Electric",
        "product_pattern": r"MELSEC-F|FX5U|FX5UC|FX5UJ|FX3U|FX3G",
        "affected_versions": "*",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "MELSEC-F FX5U Information Disclosure",
        "description": (
            "Mitsubishi Electric MELSEC-F series FX5U PLCs disclose sensitive "
            "information including user credentials in cleartext via the "
            "MELSEC protocol, enabling credential theft."
        ),
        "has_public_exploit": False,
        "epss_score": 0.09,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-21-280-04",
        "remediation": "Apply firmware updates. Use VPN or encrypted tunnels for MELSEC communications.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-21-280-04",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-20594",
        ],
    },
    {
        "cve_id": "CVE-2024-0802",
        "vendor": "Mitsubishi Electric",
        "product_pattern": r"MELSEC-Q|MELSEC-L|MELSEC\s*iQ-R|Q\d{2,}|L\d{2,}|iQ-R",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "MELSEC-Q/L/iQ-R MELSEC Protocol RCE",
        "description": (
            "Mitsubishi Electric MELSEC-Q, MELSEC-L, and iQ-R series PLCs are "
            "vulnerable to remote code execution via specially crafted MELSEC "
            "protocol messages, allowing full device compromise."
        ),
        "has_public_exploit": False,
        "epss_score": 0.36,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-24-045-01",
        "remediation": "Apply vendor firmware updates immediately. Restrict MELSEC protocol access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-24-045-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0802",
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    #  HONEYWELL  (4 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2023-24480",
        "vendor": "Honeywell",
        "product_pattern": r"OneWireless|ICS\s*Gateway|Honeywell\s*OneWireless",
        "affected_versions": "<322.2",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Honeywell OneWireless ICS Gateway RCE",
        "description": (
            "Honeywell OneWireless Wireless Device Manager contains a "
            "critical vulnerability allowing unauthenticated remote code "
            "execution on the ICS gateway, compromising the wireless "
            "field device network."
        ),
        "has_public_exploit": False,
        "epss_score": 0.34,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-23-145-01",
        "remediation": "Update to OneWireless V322.2 or later. Segment the wireless gateway network.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-145-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-24480",
        ],
    },
    {
        "cve_id": "CVE-2022-30315",
        "vendor": "Honeywell",
        "product_pattern": r"Saia\s*Burgess|PCD|Saia\s*PCD",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Honeywell Saia Burgess PCD Controller Vulnerability",
        "description": (
            "Honeywell Saia Burgess PCD controllers contain a critical "
            "vulnerability allowing unauthenticated remote attackers to "
            "modify the PLC program and compromise process control."
        ),
        "has_public_exploit": True,
        "epss_score": 0.88,
        "is_cisa_kev": False,
        "exploit_maturity": "functional",
        "ics_cert_advisory": "ICSA-22-207-03",
        "remediation": "Apply firmware updates. Restrict network access to the PCD controller.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-207-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-30315",
        ],
    },
    {
        "cve_id": "CVE-2021-38397",
        "vendor": "Honeywell",
        "product_pattern": r"Experion\s*PKS|Experion|C200|C300|ACE",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 10.0,
        "title": "Honeywell Experion PKS Remote Code Execution",
        "description": (
            "Honeywell Experion PKS distributed control system contains a "
            "critical vulnerability (CVSS 10.0) allowing unauthenticated "
            "remote code execution on the DCS server, granting full control "
            "of the process control system."
        ),
        "has_public_exploit": False,
        "epss_score": 0.39,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-21-278-04",
        "remediation": "Apply Honeywell patches immediately. Isolate the Experion PKS network.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-21-278-04",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-38397",
        ],
    },
    {
        "cve_id": "CVE-2020-7927",
        "vendor": "Honeywell",
        "product_pattern": r"C300|Honeywell\s*C300|Experion\s*C300",
        "affected_versions": "*",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "Honeywell C300 DCS Controller Denial-of-Service",
        "description": (
            "Honeywell Experion PKS C300 DCS controllers are vulnerable to "
            "denial-of-service via crafted network packets, causing the "
            "controller to become unresponsive and halt process control."
        ),
        "has_public_exploit": False,
        "epss_score": 0.07,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-20-056-03",
        "remediation": "Apply firmware updates. Implement network segmentation for DCS traffic.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-20-056-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7927",
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    #  YOKOGAWA  (3 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2022-23401",
        "vendor": "Yokogawa",
        "product_pattern": r"CENTUM\s*VP|CENTUM|Yokogawa\s*CENTUM",
        "affected_versions": "<R6.09",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "Yokogawa CENTUM VP DCS Information Disclosure",
        "description": (
            "Yokogawa CENTUM VP distributed control system exposes sensitive "
            "operational data to unauthenticated network requests, potentially "
            "revealing process control parameters."
        ),
        "has_public_exploit": False,
        "epss_score": 0.08,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-22-083-01",
        "remediation": "Update to CENTUM VP R6.09 or later. Restrict DCS network access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-083-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-23401",
        ],
    },
    {
        "cve_id": "CVE-2023-26593",
        "vendor": "Yokogawa",
        "product_pattern": r"STARDOM|FCN|FCJ|Yokogawa\s*STARDOM",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Yokogawa STARDOM FCN/FCJ Controller Authentication Bypass",
        "description": (
            "Yokogawa STARDOM FCN and FCJ network controllers contain an "
            "authentication bypass that allows unauthenticated remote "
            "attackers to modify controller configuration and control logic."
        ),
        "has_public_exploit": False,
        "epss_score": 0.23,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-23-073-02",
        "remediation": "Apply Yokogawa patches. Enable authentication and restrict network access.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-073-02",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-26593",
        ],
    },
    {
        "cve_id": "CVE-2019-5909",
        "vendor": "Yokogawa",
        "product_pattern": r"CENTUM\s*CS\s*3000|CS3000|CENTUM\s*CS|Yokogawa\s*CS",
        "affected_versions": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "title": "Yokogawa CENTUM CS 3000 Buffer Overflow",
        "description": (
            "Yokogawa CENTUM CS 3000 DCS contains a buffer overflow "
            "vulnerability that allows unauthenticated remote attackers to "
            "execute arbitrary code on the DCS server."
        ),
        "has_public_exploit": False,
        "epss_score": 0.30,
        "is_cisa_kev": False,
        "exploit_maturity": "poc",
        "ics_cert_advisory": "ICSA-19-073-01",
        "remediation": "Migrate to CENTUM VP or apply vendor patches. Isolate the DCS network.",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-19-073-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-5909",
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    #  CROSS-VENDOR / PROTOCOL-LEVEL CVEs  (5 CVEs)
    # ═══════════════════════════════════════════════════════════════════

    {
        "cve_id": "CVE-2020-15791",
        "vendor": "Generic",
        "product_pattern": r"Modbus|Modbus/TCP|modbus",
        "affected_versions": "*",
        "severity": "medium",
        "cvss_score": 6.5,
        "title": "Modbus/TCP Unauthenticated Write (Protocol Design Flaw)",
        "description": (
            "The Modbus/TCP protocol (by design) does not include "
            "authentication or encryption. Any network host can send write "
            "commands to Modbus devices, enabling unauthorized modification "
            "of registers and coils."
        ),
        "has_public_exploit": False,
        "epss_score": 0.04,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "",
        "remediation": (
            "Segment Modbus traffic. Deploy Modbus-aware firewalls. "
            "Consider migration to Modbus/TCP Security (TLS)."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-15791",
            "https://www.cisa.gov/news-events/ics-advisories/icsa-20-042-02",
        ],
    },
    {
        "cve_id": "CVE-2020-9460",
        "vendor": "OPC Foundation",
        "product_pattern": r"OPC-UA|OPC\s*UA|OPCUA",
        "affected_versions": "<1.04",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "OPC-UA .NET Standard Stack Denial-of-Service",
        "description": (
            "The OPC Foundation OPC-UA .NET Standard stack is vulnerable to "
            "denial-of-service via specially crafted OPC-UA messages, causing "
            "the server application to consume excessive memory and crash."
        ),
        "has_public_exploit": False,
        "epss_score": 0.10,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-20-163-02",
        "remediation": "Update to OPC-UA .NET Standard stack V1.04 or later.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-9460",
            "https://www.cisa.gov/news-events/ics-advisories/icsa-20-163-02",
        ],
    },
    {
        "cve_id": "CVE-2022-29862",
        "vendor": "OPC Foundation",
        "product_pattern": r"OPC-UA|OPC\s*UA|OPCUA",
        "affected_versions": "<1.04.368",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "OPC-UA Infinite Loop Denial-of-Service",
        "description": (
            "The OPC-UA stack contains an infinite loop vulnerability that "
            "can be triggered by crafted OPC-UA messages, causing the OPC-UA "
            "server to become unresponsive."
        ),
        "has_public_exploit": False,
        "epss_score": 0.06,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-22-228-02",
        "remediation": "Update the OPC-UA stack to V1.04.368 or later.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-29862",
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-228-02",
        ],
    },
    {
        "cve_id": "CVE-2023-27321",
        "vendor": "OPC Foundation",
        "product_pattern": r"OPC-UA|OPC\s*UA|OPCUA",
        "affected_versions": "<1.04.371",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "OPC-UA .NET Stack Type Confusion",
        "description": (
            "The OPC Foundation OPC-UA .NET stack is vulnerable to type "
            "confusion attacks via crafted messages, which can lead to "
            "denial-of-service or information disclosure."
        ),
        "has_public_exploit": False,
        "epss_score": 0.05,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "ICSA-23-180-01",
        "remediation": "Update the OPC-UA .NET stack to V1.04.371 or later.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-27321",
            "https://www.cisa.gov/news-events/ics-advisories/icsa-23-180-01",
        ],
    },
    {
        "cve_id": "CVE-2020-25078",
        "vendor": "D-Link",
        "product_pattern": r"D-Link|DCS|DCS-\d+",
        "affected_versions": "*",
        "severity": "high",
        "cvss_score": 7.5,
        "title": "D-Link DCS Information Disclosure",
        "description": (
            "D-Link DCS series IP cameras expose administrative credentials "
            "via unauthenticated HTTP requests, potentially compromising "
            "video surveillance feeds in OT environments."
        ),
        "has_public_exploit": False,
        "epss_score": 0.11,
        "is_cisa_kev": False,
        "exploit_maturity": "unknown",
        "ics_cert_advisory": "",
        "remediation": "Apply firmware updates. Change default credentials. Segment camera networks.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-25078",
        ],
    },
]
