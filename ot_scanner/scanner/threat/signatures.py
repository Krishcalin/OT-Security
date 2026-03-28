"""
ICS Malware Signature Database for the OT Passive Scanner.

Each signature describes a known ICS malware family's network behavior
pattern that can be detected from passive PCAP analysis. Signatures
are matched against device state, protocol stats, session state, and
communication patterns.

References:
  - CISA ICS-CERT advisories
  - Dragos threat intelligence reports
  - MITRE ATT&CK for ICS (https://attack.mitre.org/matrices/ics/)
"""

from typing import Dict, List


ICS_MALWARE_SIGNATURES: List[Dict] = [

    # ══════════════════════════════════════════════════════════════════
    #  INDUSTROYER / CRASHOVERRIDE  (2016 Ukraine power grid attack)
    # ══════════════════════════════════════════════════════════════════
    {
        "name": "Industroyer/CrashOverride",
        "description": (
            "IEC 60870-5-104 device receiving control commands (ASDU Type 45-51), "
            "general interrogation (Type 100), and clock synchronization (Type 103) "
            "from the same master in rapid succession — consistent with automated "
            "breaker-tripping attack pattern used in 2016 Ukraine grid attack."
        ),
        "severity": "critical",
        "mitre_technique": "T0855",
        "mitre_tactic": "Inhibit Response Function",
        "match_fn": "match_industroyer",
        "references": [
            "https://attack.mitre.org/software/S0604/",
            "CISA Alert AA22-103A",
        ],
    },

    # ══════════════════════════════════════════════════════════════════
    #  TRITON / TRISIS  (2017 Saudi petrochemical SIS attack)
    # ══════════════════════════════════════════════════════════════════
    {
        "name": "TRITON/TRISIS",
        "description": (
            "Safety instrumented system (SIS) device with both program download "
            "and firmware update activity detected — consistent with TRITON malware "
            "that reprograms Triconex safety controllers to disable safety functions."
        ),
        "severity": "critical",
        "mitre_technique": "T0839",
        "mitre_tactic": "Inhibit Response Function",
        "match_fn": "match_triton",
        "references": [
            "https://attack.mitre.org/software/S0609/",
            "Dragos XENOTIME threat group",
        ],
    },

    # ══════════════════════════════════════════════════════════════════
    #  HAVEX  (2014 ICS reconnaissance / OPC-UA scanning)
    # ══════════════════════════════════════════════════════════════════
    {
        "name": "Havex",
        "description": (
            "OPC-UA device with abnormally high peer count (>10 unique peers) "
            "combined with diagnostic/browse commands — consistent with Havex RAT "
            "OPC scanner module used for ICS asset discovery and intelligence gathering."
        ),
        "severity": "high",
        "mitre_technique": "T0846",
        "mitre_tactic": "Discovery",
        "match_fn": "match_havex",
        "references": [
            "https://attack.mitre.org/software/S0601/",
            "Dragos DYMALLOY threat group",
        ],
    },

    # ══════════════════════════════════════════════════════════════════
    #  BLACKENERGY  (2015 Ukraine power grid attack)
    # ══════════════════════════════════════════════════════════════════
    {
        "name": "BlackEnergy",
        "description": (
            "Device running multiple industrial protocols alongside IT protocols "
            "(HTTP, SSH, RDP) with program upload activity — consistent with "
            "BlackEnergy modular malware used for initial access and lateral movement "
            "in OT networks prior to destructive attacks."
        ),
        "severity": "high",
        "mitre_technique": "T0869",
        "mitre_tactic": "Initial Access",
        "match_fn": "match_blackenergy",
        "references": [
            "https://attack.mitre.org/software/S0089/",
            "CISA Alert AA22-110A",
        ],
    },

    # ══════════════════════════════════════════════════════════════════
    #  PIPEDREAM / INCONTROLLER  (2022 multi-protocol ICS attack tool)
    # ══════════════════════════════════════════════════════════════════
    {
        "name": "Pipedream/Incontroller",
        "description": (
            "S7comm device receiving program download activity combined with "
            "Modbus write commands to coils from the same source IP — consistent "
            "with Pipedream/Incontroller multi-protocol attack framework targeting "
            "Siemens and Schneider PLCs."
        ),
        "severity": "critical",
        "mitre_technique": "T0836",
        "mitre_tactic": "Execution",
        "match_fn": "match_pipedream",
        "references": [
            "https://attack.mitre.org/software/S1045/",
            "Dragos CHERNOVITE threat group",
            "CISA Alert AA22-103A",
        ],
    },

    # ══════════════════════════════════════════════════════════════════
    #  STUXNET  (2010 Iranian nuclear centrifuge sabotage)
    # ══════════════════════════════════════════════════════════════════
    {
        "name": "Stuxnet",
        "description": (
            "S7comm device with both program upload (PLC code read) and program "
            "download (PLC code write) from different source IPs — consistent with "
            "Stuxnet's pattern of capturing legitimate PLC logic, modifying it, "
            "and re-injecting the weaponized version."
        ),
        "severity": "critical",
        "mitre_technique": "T0843",
        "mitre_tactic": "Execution",
        "match_fn": "match_stuxnet",
        "references": [
            "https://attack.mitre.org/software/S0603/",
        ],
    },

    # ══════════════════════════════════════════════════════════════════
    #  FROSTYGOOP  (2024 Modbus-based heating system attack)
    # ══════════════════════════════════════════════════════════════════
    {
        "name": "FrostyGoop",
        "description": (
            "Modbus device receiving write commands (FC 5/6/15/16) targeting "
            "multiple unique register/coil addresses from a source in a higher "
            "Purdue level zone — consistent with FrostyGoop malware that directly "
            "manipulated Modbus registers to disrupt heating systems."
        ),
        "severity": "high",
        "mitre_technique": "T0855",
        "mitre_tactic": "Impair Process Control",
        "match_fn": "match_frostygoop",
        "references": [
            "Dragos FrostyGoop ICS malware analysis (2024)",
            "CISA Advisory on Modbus-based OT attacks",
        ],
    },
]
