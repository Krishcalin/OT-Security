"""Modules 2-5: Authentication, API, Procurement Controls, Data Protection"""
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any
from modules.base import BaseAuditor

# ═══ Module 2: Authentication & SSO ═══
class AuthenticationAuditor(BaseAuditor):
    PASSWORD_BASELINE={"minLength":(8,">="),"requireUppercase":(True,"=="),"requireDigit":(True,"=="),
        "requireSpecial":(True,"=="),"maxAge":(90,"<="),"historyCount":(5,">="),"lockoutThreshold":(5,"<=")}
    def run_all_checks(self)->List[Dict]:
        self.check_sso_config(); self.check_mfa_enforcement()
        self.check_password_policy(); self.check_session_security()
        self.check_ip_restrictions(); self.check_certificate_expiry()
        return self.findings
    def check_sso_config(self):
        sso=self.data.get("sso_config")
        if not sso: self.finding("AUTH-001","No SSO/SAML configuration found",self.SEVERITY_HIGH,
            "Authentication & SSO","Cannot verify SAML SSO setup.",
            remediation="Configure SAML 2.0 SSO with corporate IDP.",references=["SAP Ariba — SAML SSO"]); return
        cfg=sso if isinstance(sso,dict) else {}; issues=[]
        if not cfg.get("ssoEnabled",cfg.get("enabled",False)): issues.append("SAML SSO: not enabled")
        if not cfg.get("signedAssertions",True): issues.append("Signed assertions: disabled")
        if not cfg.get("encryptedAssertions",False): issues.append("Encrypted assertions: disabled")
        if cfg.get("allowIdpInitiated",True): issues.append("IDP-initiated SSO: enabled (CSRF risk)")
        if not cfg.get("enforceSSO",False): issues.append("SSO enforcement: not mandatory (password fallback)")
        if issues:
            self.finding("AUTH-002","SAML SSO configuration weaknesses",
                self.SEVERITY_CRITICAL if "not enabled" in str(issues) else self.SEVERITY_HIGH,
                "Authentication & SSO",f"{len(issues)} SSO issue(s).",issues,
                "Enable SAML SSO with signed+encrypted assertions. Enforce SSO (disable password fallback).",
                ["SAP Ariba Security Guide — SAML","SSPM — SSO Configuration"])
    def check_mfa_enforcement(self):
        mfa=self.data.get("mfa_config")
        if not mfa: self.finding("AUTH-003","No MFA configuration found",self.SEVERITY_HIGH,
            "Authentication & SSO","MFA may not be enforced.",
            remediation="Enable MFA via IDP integration.",references=["SSPM — MFA Coverage"]); return
        cfg=mfa if isinstance(mfa,dict) else {}; issues=[]
        if not cfg.get("enabled",False): issues.append("MFA: not enabled")
        if not cfg.get("adminMfa",False): issues.append("MFA for admins: not separately enforced")
        if cfg.get("allowBypass",False): issues.append("MFA bypass: allowed")
        methods=cfg.get("methods",[])
        if "SMS" in [str(m).upper() for m in methods]: issues.append("SMS MFA: allowed (SIM swap risk)")
        if issues:
            self.finding("AUTH-004","MFA configuration gaps",self.SEVERITY_HIGH,"Authentication & SSO",
                f"{len(issues)} MFA issue(s).",issues,"Enable MFA for all users. Enforce for admins. Disable SMS.",
                ["SAP Ariba — MFA Best Practices","SSPM — MFA Enforcement"])
    def check_password_policy(self):
        pp=self.data.get("password_policy")
        if not pp: return
        cfg=pp if isinstance(pp,dict) else {}; violations=[]
        for k,(exp,op) in self.PASSWORD_BASELINE.items():
            v=cfg.get(k)
            if v is None: continue
            if isinstance(exp,bool):
                if str(v).lower() not in (str(exp).lower(),"1","yes","true"):
                    violations.append(f"{k}: {v} (expected: {exp})")
            elif op==">=":
                try:
                    if int(str(v))<int(str(exp)): violations.append(f"{k}: {v} (min: {exp})")
                except ValueError: pass
            elif op=="<=":
                try:
                    if int(str(v))>int(str(exp)): violations.append(f"{k}: {v} (max: {exp})")
                except ValueError: pass
        if violations:
            self.finding("AUTH-005","Password policy below baseline",self.SEVERITY_HIGH,
                "Authentication & SSO",f"{len(violations)} weakness(es).",violations,
                "Strengthen password policy settings.",["SAP Ariba — Password Configuration"])
    def check_session_security(self):
        sso=self.data.get("sso_config") or {}
        timeout=sso.get("sessionTimeout",sso.get("session_timeout",0))
        if timeout:
            try:
                if int(str(timeout))>30:
                    self.finding("AUTH-006",f"Session timeout too long ({timeout} min)",self.SEVERITY_MEDIUM,
                        "Authentication & SSO",f"Timeout: {timeout}m (max: 30).",
                        remediation="Set session timeout to 15-30 minutes.",references=["SSPM — Session Security"])
            except ValueError: pass
    def check_ip_restrictions(self):
        ipr=self.data.get("ip_restrictions")
        if not ipr: return
        cfg=ipr if isinstance(ipr,dict) else {}
        if not cfg.get("enabled",False):
            self.finding("AUTH-007","IP restrictions not enabled",self.SEVERITY_MEDIUM,
                "Authentication & SSO","No IP-based access restrictions.",
                remediation="Enable IP restrictions for admin access.",references=["SSPM — Network Controls"])
    def check_certificate_expiry(self):
        enc=self.data.get("encryption_config")
        if not enc: return
        certs=enc.get("certificates",[]) if isinstance(enc,dict) else enc if isinstance(enc,list) else []
        now=datetime.now(); issues=[]
        for c in certs:
            if not isinstance(c,dict): continue
            name=c.get("name","unknown"); exp=c.get("expiryDate",c.get("validTo",""))
            if exp:
                for fmt in ("%Y-%m-%d","%m/%d/%Y"):
                    try:
                        d=datetime.strptime(exp.strip()[:10],fmt); days=(d-now).days
                        if days<=0: issues.append(f"{name}: EXPIRED {abs(days)}d ago")
                        elif days<=90: issues.append(f"{name}: expires in {days}d")
                        break
                    except ValueError: continue
        if issues:
            self.finding("AUTH-008","Certificates expiring or expired",
                self.SEVERITY_CRITICAL if any("EXPIRED" in i for i in issues) else self.SEVERITY_HIGH,
                "Authentication & SSO",f"{len(issues)} certificate(s).",issues,
                "Renew certificates before expiry.",["SAP Ariba — Certificate Management"])

# ═══ Module 3: API & Integration Security ═══
class ApiIntegrationAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_api_client_security(); self.check_api_permissions()
        self.check_integration_auth(); self.check_webhook_security()
        self.check_api_rate_limiting()
        return self.findings
    def check_api_client_security(self):
        clients=self.data.get("api_clients")
        if not clients: return
        cl=clients if isinstance(clients,list) else clients.get("clients",[])
        broad=[]; stale=[]; deprecated=[]; now=datetime.now()
        for c in cl:
            if not isinstance(c,dict): continue
            cid=c.get("clientId",c.get("name","unknown"))
            scopes=str(c.get("scopes",[])).upper()
            grants=str(c.get("grantTypes",[])).upper()
            last=c.get("lastUsed",c.get("lastAccess",""))
            if any(w in scopes for w in ["*","ADMIN","ALL","FULL"]): broad.append(f"{cid}: scopes={c.get('scopes')}")
            if any(d in grants for d in ["PASSWORD","IMPLICIT"]): deprecated.append(f"{cid}: grants={c.get('grantTypes')}")
            if last:
                for fmt in ("%Y-%m-%d",):
                    try:
                        d=datetime.strptime(last[:10],fmt)
                        if (now-d).days>180: stale.append(f"{cid}: last used {last}")
                        break
                    except ValueError: continue
        if broad: self.finding("API-001","API clients with overly broad scopes",self.SEVERITY_HIGH,
            "API & Integration",f"{len(broad)} client(s).",broad,
            "Restrict API scopes to minimum required.",["SAP Ariba API Security","SSPM — OAuth Scopes"])
        if deprecated: self.finding("API-002","API clients using deprecated grant types",self.SEVERITY_HIGH,
            "API & Integration",f"{len(deprecated)} client(s).",deprecated,
            "Migrate to client_credentials or authorization_code.",["OAuth 2.1 — Deprecated Grants"])
        if stale: self.finding("API-003","Stale API clients (>180 days)",self.SEVERITY_MEDIUM,
            "API & Integration",f"{len(stale)} client(s).",stale,
            "Revoke unused API clients. Rotate secrets.",["SSPM — API Credential Lifecycle"])
    def check_api_permissions(self):
        perms=self.data.get("api_permissions")
        if not perms: return
        sensitive=["SUPPLIER","PAYMENT","CONTRACT","INVOICE","USER","PURCHASE_ORDER"]
        risky=[f"{r.get('CLIENT','')} → {r.get('ENTITY','')}: {r.get('ACCESS','')}"
              for r in perms if any(s in r.get("ENTITY","").upper() for s in sensitive)
              and r.get("ACCESS","").upper() in ("WRITE","FULL","ADMIN","DELETE")]
        if risky: self.finding("API-004","API write access to sensitive entities",self.SEVERITY_HIGH,
            "API & Integration",f"{len(risky)} assignment(s).",risky[:20],
            "Restrict API write access. Use read-only where possible.",["SAP Ariba API — Least Privilege"])
    def check_integration_auth(self):
        ic=self.data.get("integration_config")
        if not ic: return
        cfg=ic if isinstance(ic,dict) else {}
        integrations=cfg.get("integrations",cfg.get("connectors",[]))
        no_auth=[f"{i.get('name','unknown')}: auth={i.get('auth','none')}"
                for i in integrations if isinstance(i,dict) and
                not i.get("auth",i.get("authentication","")) or
                str(i.get("auth","")).upper() in ("NONE","")]
        if no_auth: self.finding("API-005","Integrations without authentication",self.SEVERITY_CRITICAL,
            "API & Integration",f"{len(no_auth)} integration(s).",no_auth,
            "Configure OAuth or certificate auth for all integrations.",
            ["SAP Ariba — Integration Security"])
    def check_webhook_security(self):
        ic=self.data.get("integration_config")
        if not ic or not isinstance(ic,dict): return
        webhooks=ic.get("webhooks",[])
        insecure=[f"{w.get('name','')}: {w.get('url','')}" for w in webhooks
                 if isinstance(w,dict) and w.get("url","").startswith("http://")]
        if insecure: self.finding("API-006","Webhooks using HTTP (not HTTPS)",self.SEVERITY_HIGH,
            "API & Integration","Webhook callbacks over unencrypted HTTP.",insecure,
            "Use HTTPS for all webhook endpoints. Enable HMAC signature verification.",
            ["SSPM — Webhook Security"])
    def check_api_rate_limiting(self):
        ic=self.data.get("integration_config")
        if not ic or not isinstance(ic,dict): return
        if not ic.get("rateLimiting",ic.get("rate_limit",{})):
            self.finding("API-007","API rate limiting not configured",self.SEVERITY_MEDIUM,
                "API & Integration","No rate limiting detected for API access.",
                remediation="Configure rate limiting to prevent API abuse.",references=["SSPM — API Controls"])

# ═══ Module 4: Procurement & Workflow Controls ═══
class ProcurementControlsAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_approval_workflows(); self.check_procurement_thresholds()
        self.check_contract_controls(); self.check_catalog_security()
        self.check_payment_controls(); self.check_po_policy()
        return self.findings
    def check_approval_workflows(self):
        wf=self.data.get("approval_workflows")
        if not wf: return
        cfg=wf if isinstance(wf,dict) else {}
        rules=cfg.get("rules",cfg.get("approvalRules",[]))
        no_approval=[r.get("name","") for r in rules if isinstance(r,dict)
                    and not r.get("approvalRequired",True)]
        auto_approve=[r.get("name","") for r in rules if isinstance(r,dict)
                     and r.get("autoApprove",False)]
        if no_approval: self.finding("PROC-001",f"Workflows without approval requirement ({len(no_approval)})",
            self.SEVERITY_HIGH,"Procurement Controls",
            "Procurement workflows bypass approval.",no_approval,
            "Require approval for all POs above threshold.",["SAP Ariba — Approval Flow Best Practices"])
        if auto_approve: self.finding("PROC-002",f"Auto-approval enabled ({len(auto_approve)} rules)",
            self.SEVERITY_MEDIUM,"Procurement Controls",
            "Auto-approval may bypass segregation of duties.",auto_approve,
            "Review auto-approval thresholds. Ensure compensating controls.",
            ["SOX — Procurement Controls"])
    def check_procurement_thresholds(self):
        pol=self.data.get("procurement_policies")
        if not pol or not isinstance(pol,dict): return
        thresh=pol.get("thresholds",{})
        po_limit=thresh.get("poAutoApproveLimit",thresh.get("auto_approve_threshold",0))
        if po_limit:
            try:
                if float(str(po_limit))>10000:
                    self.finding("PROC-003",f"High auto-approve threshold (${po_limit})",
                        self.SEVERITY_HIGH,"Procurement Controls",
                        f"POs up to ${po_limit} can be auto-approved.",
                        [f"Auto-approve limit: ${po_limit}"],
                        "Reduce auto-approval threshold. Implement tiered approvals.",
                        ["SOX — Procurement Thresholds"])
            except ValueError: pass
    def check_contract_controls(self):
        cc=self.data.get("contract_config")
        if not cc or not isinstance(cc,dict): return
        issues=[]
        if not cc.get("expiryAlerts",True): issues.append("Contract expiry alerts: disabled")
        if not cc.get("dualApproval",False): issues.append("Dual approval for contracts: not required")
        if cc.get("allowNoCompete",True): issues.append("Contracts without competitive bidding: allowed")
        if issues: self.finding("PROC-004","Contract management control gaps",self.SEVERITY_MEDIUM,
            "Procurement Controls",f"{len(issues)} issue(s).",issues,
            "Enable contract expiry alerts and dual approval.",["SAP Ariba — Contract Best Practices"])
    def check_catalog_security(self):
        cat=self.data.get("catalog_config")
        if not cat or not isinstance(cat,dict): return
        if not cat.get("approvalRequired",True):
            self.finding("PROC-005","Catalog changes without approval",self.SEVERITY_MEDIUM,
                "Procurement Controls","Catalog items can be modified without approval workflow.",
                remediation="Require approval for catalog price/item changes.",
                references=["SAP Ariba — Catalog Governance"])
    def check_payment_controls(self):
        pay=self.data.get("payment_config")
        if not pay or not isinstance(pay,dict): return
        issues=[]
        if not pay.get("threeWayMatch",True): issues.append("Three-way match: not enforced")
        if not pay.get("duplicateCheck",True): issues.append("Duplicate payment detection: disabled")
        if pay.get("autoPayEnabled",False) and not pay.get("autoPayApproval",True):
            issues.append("Auto-payment without approval: enabled")
        if issues: self.finding("PROC-006","Payment control weaknesses",self.SEVERITY_HIGH,
            "Procurement Controls",f"{len(issues)} issue(s).",issues,
            "Enable 3-way matching and duplicate detection.",["SOX — Payment Controls"])
    def check_po_policy(self):
        pol=self.data.get("procurement_policies")
        if not pol or not isinstance(pol,dict): return
        if pol.get("allowMaverickSpend",True):
            self.finding("PROC-007","Maverick spending allowed",self.SEVERITY_MEDIUM,
                "Procurement Controls","Purchases outside approved catalogs/contracts allowed.",
                remediation="Enforce guided buying. Restrict off-catalog purchases.",
                references=["SAP Ariba — Guided Buying"])

# ═══ Module 5: Data Protection & Privacy ═══
class DataProtectionAuditor(BaseAuditor):
    PII_PATTERNS=["SSN","TAX_ID","BANK_ACCOUNT","IBAN","ROUTING","SALARY","CREDIT_CARD",
                  "PASSPORT","NATIONAL_ID","DATE_OF_BIRTH","PHONE","EMAIL","ADDRESS"]
    def run_all_checks(self)->List[Dict]:
        self.check_data_sharing(); self.check_field_encryption()
        self.check_data_retention(); self.check_custom_field_pii()
        self.check_export_controls(); self.check_supplier_data_exposure()
        return self.findings
    def check_data_sharing(self):
        ds=self.data.get("data_sharing")
        if not ds or not isinstance(ds,dict): return
        external=ds.get("externalSharing",ds.get("sharing_rules",[]))
        broad=[f"{r.get('name','')}: scope={r.get('scope','')}" for r in external
              if isinstance(r,dict) and r.get("scope","").upper() in ("ALL","PUBLIC","EVERYONE")]
        if broad: self.finding("DATA-001","Overly broad external data sharing",self.SEVERITY_HIGH,
            "Data Protection",f"{len(broad)} sharing rule(s) expose data broadly.",broad,
            "Restrict external sharing to specific partners/domains.",
            ["SSPM — Data Sharing Controls","GDPR Art. 5"])
    def check_field_encryption(self):
        enc=self.data.get("encryption_config")
        if not enc or not isinstance(enc,dict): return
        if not enc.get("fieldLevelEncryption",enc.get("sensitiveFieldEncryption",False)):
            self.finding("DATA-002","Field-level encryption not enabled",self.SEVERITY_HIGH,
                "Data Protection","Sensitive fields (bank details, tax IDs) may not be encrypted at rest.",
                remediation="Enable field-level encryption for PII fields.",
                references=["SAP Ariba — Data Encryption","SSPM — Data at Rest"])
    def check_data_retention(self):
        ret=self.data.get("compliance_config")
        if not ret or not isinstance(ret,dict): return
        policies=ret.get("retentionPolicies",ret.get("retention",[]))
        if not policies:
            self.finding("DATA-003","No data retention policies configured",self.SEVERITY_HIGH,
                "Data Protection","Data retained indefinitely violates data minimization.",
                remediation="Configure retention and purge policies.",
                references=["GDPR Art. 5(1)(e)","SAP Ariba — Data Retention"])
    def check_custom_field_pii(self):
        fields=self.data.get("custom_fields")
        if not fields: return
        unprotected=[f"{f.get('FIELD_NAME','')}: classification={f.get('CLASSIFICATION','none')}"
                    for f in fields if any(p in f.get("FIELD_NAME","").upper() for p in self.PII_PATTERNS)
                    and f.get("CLASSIFICATION","").upper() not in ("PII","SENSITIVE","CONFIDENTIAL")]
        if unprotected: self.finding("DATA-004","Custom fields with PII not classified",self.SEVERITY_HIGH,
            "Data Protection",f"{len(unprotected)} field(s).",unprotected[:20],
            "Classify PII fields and enable encryption/masking.",["SSPM — Data Classification"])
    def check_export_controls(self):
        pol=self.data.get("procurement_policies")
        if not pol or not isinstance(pol,dict): return
        if pol.get("bulkExportEnabled",True):
            self.finding("DATA-005","Bulk data export enabled",self.SEVERITY_MEDIUM,
                "Data Protection","Users can export large datasets containing sensitive procurement data.",
                remediation="Restrict bulk export to admin roles. Enable export audit logging.",
                references=["SSPM — Data Export Controls"])
    def check_supplier_data_exposure(self):
        sc=self.data.get("supplier_config")
        if not sc or not isinstance(sc,dict): return
        if sc.get("supplierSelfService",{}).get("viewOtherSuppliers",False):
            self.finding("DATA-006","Suppliers can view other supplier information",self.SEVERITY_HIGH,
                "Data Protection","Supplier self-service portal exposes other supplier data.",
                remediation="Restrict supplier portal visibility to own data only.",
                references=["SAP Ariba Network — Supplier Isolation"])
