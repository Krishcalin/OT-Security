"""Modules 6-10: Supplier, Audit, Network, Notification, Config Drift"""
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any
from modules.base import BaseAuditor

# ═══ Module 6: Supplier Management Security ═══
class SupplierSecurityAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_supplier_onboarding(); self.check_supplier_auth()
        self.check_supplier_data_validation(); self.check_supplier_risk()
        return self.findings
    def check_supplier_onboarding(self):
        sc=self.data.get("supplier_config")
        if not sc or not isinstance(sc,dict): return
        onb=sc.get("onboarding",{})
        issues=[]
        if not onb.get("approvalRequired",True): issues.append("Supplier onboarding: no approval required")
        if not onb.get("dueDiligence",False): issues.append("Due diligence checks: not configured")
        if not onb.get("riskAssessment",False): issues.append("Supplier risk assessment: not enabled")
        if onb.get("selfRegistration",True) and not onb.get("selfRegApproval",True):
            issues.append("Self-registration without approval: enabled")
        if issues: self.finding("SUPP-001",f"Supplier onboarding control gaps ({len(issues)})",
            self.SEVERITY_HIGH,"Supplier Management",
            "Weak supplier onboarding controls increase supply chain risk.",issues,
            "Require approval and due diligence for all new suppliers.",
            ["SAP Ariba — Supplier Lifecycle","SSPM — Third-Party Risk"])
    def check_supplier_auth(self):
        sc=self.data.get("supplier_config")
        if not sc or not isinstance(sc,dict): return
        auth=sc.get("authentication",{})
        if not auth.get("mfaRequired",False):
            self.finding("SUPP-002","Supplier MFA not enforced",self.SEVERITY_MEDIUM,
                "Supplier Management","Suppliers can access the network without MFA.",
                remediation="Enforce MFA for supplier portal access.",
                references=["SAP Ariba Network — Supplier Authentication"])
    def check_supplier_data_validation(self):
        sc=self.data.get("supplier_config")
        if not sc or not isinstance(sc,dict): return
        val=sc.get("dataValidation",{})
        if not val.get("bankDetailVerification",False):
            self.finding("SUPP-003","Supplier bank detail verification not enabled",self.SEVERITY_CRITICAL,
                "Supplier Management","Bank account changes not verified — BEC/invoice fraud vector.",
                remediation="Enable bank detail verification with multi-channel confirmation.",
                references=["SAP Ariba — Supplier Master Data","BEC Fraud Prevention"])
    def check_supplier_risk(self):
        sc=self.data.get("supplier_config")
        if not sc or not isinstance(sc,dict): return
        if not sc.get("continuousMonitoring",False):
            self.finding("SUPP-004","Supplier continuous risk monitoring disabled",self.SEVERITY_MEDIUM,
                "Supplier Management","Supplier risk is only assessed at onboarding, not continuously.",
                remediation="Enable continuous supplier risk monitoring.",
                references=["SAP Ariba Supplier Risk — Continuous Monitoring"])

# ═══ Module 7: Audit & Compliance ═══
class AuditComplianceAuditor(BaseAuditor):
    REQUIRED_LOG_TYPES=["user_login","user_logout","config_change","role_change","po_create",
        "po_approve","invoice_process","supplier_change","contract_change","data_export"]
    def run_all_checks(self)->List[Dict]:
        self.check_audit_logging(); self.check_audit_log_types()
        self.check_log_retention(); self.check_siem_integration()
        self.check_compliance_framework()
        return self.findings
    def check_audit_logging(self):
        ac=self.data.get("audit_config")
        if not ac:
            self.finding("AUDIT-001","No audit log configuration found",self.SEVERITY_HIGH,
                "Audit & Compliance","Cannot verify audit logging setup.",
                remediation="Enable comprehensive audit logging.",references=["SAP Ariba — Audit Service"]); return
        cfg=ac if isinstance(ac,dict) else {}
        if not cfg.get("enabled",True):
            self.finding("AUDIT-002","Audit logging disabled",self.SEVERITY_CRITICAL,
                "Audit & Compliance","Audit logging is not enabled.",
                remediation="Enable audit logging immediately.",references=["SOX — Audit Trail"])
    def check_audit_log_types(self):
        ac=self.data.get("audit_config")
        if not ac or not isinstance(ac,dict): return
        logged=set(str(t).lower() for t in ac.get("loggedEvents",ac.get("eventTypes",[])))
        missing=[t for t in self.REQUIRED_LOG_TYPES if t not in logged and "all" not in logged]
        if missing: self.finding("AUDIT-003",f"Audit log types missing ({len(missing)})",
            self.SEVERITY_HIGH,"Audit & Compliance",f"{len(missing)} event type(s) not logged.",
            [f"Missing: {t}" for t in missing],"Enable logging for all listed event types.",
            ["SAP Ariba — Audit History","SSPM — Audit Coverage"])
    def check_log_retention(self):
        ac=self.data.get("audit_config")
        if not ac or not isinstance(ac,dict): return
        days=ac.get("retentionDays",ac.get("retention",0))
        try:
            if int(str(days))<365:
                self.finding("AUDIT-004",f"Audit log retention below 365 days ({days}d)",
                    self.SEVERITY_MEDIUM,"Audit & Compliance",f"Retention: {days} days.",
                    remediation="Set retention to 365+ days. Export to SIEM for long-term storage.",
                    references=["SOX — Log Retention","SSPM — Audit Retention"])
        except ValueError: pass
    def check_siem_integration(self):
        ac=self.data.get("audit_config")
        if not ac or not isinstance(ac,dict): return
        if not ac.get("siemExport",ac.get("externalForwarding",False)):
            self.finding("AUDIT-005","Audit logs not forwarded to SIEM",self.SEVERITY_MEDIUM,
                "Audit & Compliance","Logs not exported to external SIEM/SOAR.",
                remediation="Configure log export to SIEM (Splunk, Sentinel, QRadar).",
                references=["SSPM — SIEM Integration"])
    def check_compliance_framework(self):
        cc=self.data.get("compliance_config")
        if not cc or not isinstance(cc,dict): return
        frameworks=cc.get("frameworks",cc.get("standards",[]))
        if not frameworks:
            self.finding("AUDIT-006","No compliance framework configured",self.SEVERITY_LOW,
                "Audit & Compliance","No compliance framework alignment documented.",
                remediation="Map controls to SOX, GDPR, ISO 27001 as applicable.",
                references=["SSPM — Compliance Mapping"])

# ═══ Module 8: Network & Ariba Network Security ═══
class NetworkSecurityAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_network_access(); self.check_tls_config()
        self.check_network_sharing()
        return self.findings
    def check_network_access(self):
        nc=self.data.get("network_config")
        if not nc or not isinstance(nc,dict): return
        if nc.get("publicProfileEnabled",True):
            self.finding("NET-001","Ariba Network public profile enabled",self.SEVERITY_MEDIUM,
                "Network Security","Organization profile visible to all Ariba Network members.",
                remediation="Restrict profile visibility to approved trading partners.",
                references=["SAP Ariba Network — Profile Privacy"])
    def check_tls_config(self):
        enc=self.data.get("encryption_config")
        if not enc or not isinstance(enc,dict): return
        tls=enc.get("minTlsVersion",enc.get("tls_minimum",""))
        if tls and tls.lower() in ("tls1.0","tls1.1","tlsv1","tlsv1.1"):
            self.finding("NET-002",f"Minimum TLS version too low ({tls})",self.SEVERITY_HIGH,
                "Network Security","TLS 1.0/1.1 have known vulnerabilities.",
                remediation="Set minimum TLS 1.2.",references=["NIST SP 800-52 Rev 2"])
    def check_network_sharing(self):
        nc=self.data.get("network_config")
        if not nc or not isinstance(nc,dict): return
        if nc.get("autoShareDocuments",False):
            self.finding("NET-003","Automatic document sharing enabled on Ariba Network",
                self.SEVERITY_MEDIUM,"Network Security",
                "Documents auto-shared with all trading partners.",
                remediation="Disable auto-sharing. Use explicit document sharing workflows.",
                references=["SAP Ariba Network — Document Security"])

# ═══ Module 9: Notification & Alerting ═══
class NotificationAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_security_alerts(); self.check_notification_channels()
        return self.findings
    def check_security_alerts(self):
        nc=self.data.get("notification_config")
        if not nc or not isinstance(nc,dict): return
        alerts=nc.get("securityAlerts",nc.get("alertRules",[]))
        if not alerts:
            self.finding("NOTIF-001","No security alert rules configured",self.SEVERITY_HIGH,
                "Notification & Alerting","No alerts for security events (failed logins, config changes).",
                remediation="Configure alerts for: mass login failures, admin changes, bulk exports.",
                references=["SSPM — Security Alerting"])
    def check_notification_channels(self):
        nc=self.data.get("notification_config")
        if not nc or not isinstance(nc,dict): return
        channels=nc.get("channels",nc.get("notificationChannels",[]))
        if not channels or len(channels)==0:
            self.finding("NOTIF-002","No notification channels configured",self.SEVERITY_MEDIUM,
                "Notification & Alerting","No email/webhook/SIEM notification channels.",
                remediation="Configure notification channels for security events.",
                references=["SSPM — Alert Channels"])

# ═══ Module 10: Configuration Drift Detection ═══
class ConfigDriftAuditor(BaseAuditor):
    CRITICAL_SETTINGS=["ssoEnabled","mfaEnabled","auditEnabled","passwordComplexity",
        "ipRestrictions","sessionTimeout","bulkExportEnabled","autoApproveLimit",
        "fieldLevelEncryption","supplierVerification"]
    def run_all_checks(self)->List[Dict]:
        self.check_critical_settings(); self.check_baseline_drift()
        return self.findings
    def check_critical_settings(self):
        issues=[]
        sso=self.data.get("sso_config") or {}
        if isinstance(sso,dict) and not sso.get("ssoEnabled",sso.get("enabled",False)):
            issues.append("SSO: disabled")
        mfa=self.data.get("mfa_config") or {}
        if isinstance(mfa,dict) and not mfa.get("enabled",False):
            issues.append("MFA: disabled")
        ac=self.data.get("audit_config") or {}
        if isinstance(ac,dict) and not ac.get("enabled",True):
            issues.append("Audit logging: disabled")
        ipr=self.data.get("ip_restrictions") or {}
        if isinstance(ipr,dict) and not ipr.get("enabled",False):
            issues.append("IP restrictions: disabled")
        if issues: self.finding("DRIFT-001",f"Critical security settings not enabled ({len(issues)})",
            self.SEVERITY_CRITICAL,"Configuration Drift",
            f"{len(issues)} critical security setting(s) are disabled.",issues,
            "Enable all critical security controls immediately.",
            ["SSPM — Configuration Baseline","SAP Ariba — Security Hardening"])
    def check_baseline_drift(self):
        if not self.baseline: return
        drifts=[]
        configs={"sso_config":"SSO","mfa_config":"MFA","audit_config":"Audit",
                "password_policy":"Password","ip_restrictions":"IP Restrictions"}
        for key,label in configs.items():
            expected=self.baseline.get(key,{})
            actual=self.data.get(key) or {}
            if not isinstance(actual,dict) or not isinstance(expected,dict): continue
            for setting,exp_val in expected.items():
                act_val=actual.get(setting)
                if act_val is not None and str(act_val)!=str(exp_val):
                    drifts.append(f"{label}.{setting}: expected={exp_val}, actual={act_val}")
        if drifts: self.finding("DRIFT-002",f"Configuration drift from baseline ({len(drifts)} settings)",
            self.SEVERITY_HIGH,"Configuration Drift",
            f"{len(drifts)} setting(s) have drifted from the security baseline.",drifts[:30],
            "Investigate and remediate configuration drift. Re-apply baseline settings.",
            ["SSPM — Configuration Drift Detection"])
