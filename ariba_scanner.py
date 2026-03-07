#!/usr/bin/env python3
"""
SAP Ariba SSPM Security Scanner
===================================
SaaS Security Posture Management scanner for SAP Ariba procurement platform.
Analyzes configuration exports to detect misconfigurations, access risks,
compliance gaps, and security drift.

Usage:
    python ariba_scanner.py --data-dir ./sample_data --output report.html
    python ariba_scanner.py --data-dir ./exports --modules iam auth procurement
"""
import argparse,json,sys,datetime
from pathlib import Path
from modules.base import DataLoader
from modules.identity_access import IdentityAccessAuditor
from modules.core_modules import (AuthenticationAuditor,ApiIntegrationAuditor,
    ProcurementControlsAuditor,DataProtectionAuditor)
from modules.extended_modules import (SupplierSecurityAuditor,AuditComplianceAuditor,
    NetworkSecurityAuditor,NotificationAuditor,ConfigDriftAuditor)

try: from modules.report_generator import ReportGenerator
except ImportError: ReportGenerator=None

def banner():
    print(r"""
  ╔═══════════════════════════════════════════════════════════════╗
  ║   SAP Ariba SSPM Security Scanner v1.0                       ║
  ║   SaaS Security Posture Management for Procurement           ║
  ║   Identity · API · Procurement · Data · Compliance           ║
  ╚═══════════════════════════════════════════════════════════════╝
    """)

MODULE_MAP={
    "iam":("Identity & Access Management",IdentityAccessAuditor),
    "auth":("Authentication & SSO",AuthenticationAuditor),
    "api":("API & Integration Security",ApiIntegrationAuditor),
    "procurement":("Procurement & Workflow Controls",ProcurementControlsAuditor),
    "data":("Data Protection & Privacy",DataProtectionAuditor),
    "supplier":("Supplier Management Security",SupplierSecurityAuditor),
    "audit":("Audit & Compliance",AuditComplianceAuditor),
    "network":("Network Security",NetworkSecurityAuditor),
    "notification":("Notification & Alerting",NotificationAuditor),
    "drift":("Configuration Drift Detection",ConfigDriftAuditor),
}

def main():
    banner()
    parser=argparse.ArgumentParser(description="SAP Ariba SSPM Security Scanner")
    parser.add_argument("--data-dir",required=True)
    parser.add_argument("--output",default="ariba_security_report.html")
    parser.add_argument("--severity",choices=["CRITICAL","HIGH","MEDIUM","LOW","ALL"],default="ALL")
    parser.add_argument("--modules",nargs="+",choices=list(MODULE_MAP.keys())+["all"],default=["all"])
    parser.add_argument("--config",default=None,help="Baseline config JSON for drift detection")
    args=parser.parse_args()

    data_dir=Path(args.data_dir)
    if not data_dir.exists(): print(f"[ERROR] Not found: {data_dir}"); sys.exit(1)

    print("[*] Loading SAP Ariba configuration data...")
    data=DataLoader(data_dir).load_all()

    baseline={}
    if args.config:
        with open(args.config) as f: baseline=json.load(f)
        print(f"[*] Loaded baseline from {args.config}")

    run=list(MODULE_MAP.keys()) if "all" in args.modules else args.modules
    all_findings=[]
    for mod in run:
        if mod not in MODULE_MAP: continue
        label,cls=MODULE_MAP[mod]
        print(f"[*] Running {label}...")
        auditor=cls(data,baseline)
        findings=auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    sev={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    if args.severity!="ALL":
        t=sev.get(args.severity,4)
        all_findings=[f for f in all_findings if sev.get(f["severity"],4)<=t]

    meta={"scan_time":datetime.datetime.now().isoformat(),"data_directory":str(data_dir),
          "modules_run":run,"severity_filter":args.severity}

    print(f"\n[*] Generating report: {args.output}")
    if ReportGenerator:
        ReportGenerator(all_findings,meta).generate(args.output)
    else:
        import json as j
        with open(args.output.replace(".html",".json"),"w") as f:
            j.dump({"findings":all_findings,"meta":meta},f,indent=2)
        print(f"    (HTML generator not available, wrote JSON)")

    c=sum(1 for f in all_findings if f["severity"]=="CRITICAL")
    h=sum(1 for f in all_findings if f["severity"]=="HIGH")
    m=sum(1 for f in all_findings if f["severity"]=="MEDIUM")
    l=sum(1 for f in all_findings if f["severity"]=="LOW")
    print(f"\n{'='*63}")
    print(f"  SCAN COMPLETE — {len(all_findings)} finding(s)")
    print(f"  CRITICAL: {c}  |  HIGH: {h}  |  MEDIUM: {m}  |  LOW: {l}")
    print(f"  Report: {args.output}")
    print(f"{'='*63}\n")

if __name__=="__main__": main()
