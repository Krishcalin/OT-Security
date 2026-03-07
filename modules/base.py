"""Base Auditor and Data Loader for SAP Ariba SSPM Scanner."""
import csv, json, datetime
from pathlib import Path
from typing import Dict, List, Any

class BaseAuditor:
    SEVERITY_CRITICAL="CRITICAL"; SEVERITY_HIGH="HIGH"; SEVERITY_MEDIUM="MEDIUM"; SEVERITY_LOW="LOW"
    def __init__(self, data, baseline=None):
        self.data=data; self.baseline=baseline or {}; self.findings=[]
    def finding(self, check_id, title, severity, category, description,
                affected_items=None, remediation="", references=None, details=None):
        f={"check_id":check_id,"title":title,"severity":severity,"category":category,
           "description":description,"affected_items":affected_items or [],
           "affected_count":len(affected_items) if affected_items else 0,
           "remediation":remediation,"references":references or [],"details":details or {},
           "timestamp":datetime.datetime.now().isoformat()}
        self.findings.append(f); return f
    def run_all_checks(self)->List[Dict]: raise NotImplementedError
    def get_config(self,key,default): return self.baseline.get(key,default)

FILE_MAP={
    "users":["users.csv","ariba_users.csv"],"user_groups":["user_groups.csv","groups.csv"],
    "roles":["roles.csv","ariba_roles.csv"],"user_roles":["user_roles.csv","role_assignments.csv"],
    "sso_config":["sso_config.json","saml_config.json"],"password_policy":["password_policy.json"],
    "mfa_config":["mfa_config.json"],"api_clients":["api_clients.json","oauth_clients.json"],
    "api_permissions":["api_permissions.csv"],"integration_config":["integration_config.json"],
    "approval_workflows":["approval_workflows.json","workflows.json"],
    "procurement_policies":["procurement_policies.json","policies.json"],
    "supplier_config":["supplier_config.json","supplier_management.json"],
    "data_sharing":["data_sharing.json","external_sharing.json"],
    "audit_config":["audit_config.json","audit_log.json"],
    "encryption_config":["encryption_config.json","certificates.json"],
    "compliance_config":["compliance_config.json"],"ip_restrictions":["ip_restrictions.json"],
    "notification_config":["notification_config.json"],"custom_fields":["custom_fields.csv"],
    "contract_config":["contract_config.json"],"catalog_config":["catalog_config.json"],
    "payment_config":["payment_config.json"],"network_config":["network_config.json"],
    "sod_rules":["sod_rules.json","segregation_of_duties.json"],
}

class DataLoader:
    def __init__(self, data_dir):
        self.data_dir=Path(data_dir); self._data={}
    def load_all(self):
        for key,fnames in FILE_MAP.items():
            for fn in fnames:
                fp=self.data_dir/fn
                if fp.exists():
                    print(f"    Loading {fn}...")
                    if fn.endswith(".csv"): self._data[key]=self._csv(fp)
                    elif fn.endswith(".json"): self._data[key]=self._json(fp)
                    break
            else: self._data[key]=None
        loaded=[k for k,v in self._data.items() if v is not None]
        missing=[k for k,v in self._data.items() if v is None]
        print(f"    Loaded: {', '.join(loaded)}")
        if missing: print(f"    Not found: {', '.join(missing)}")
        return self._data
    def _csv(self,p):
        rows=[]
        try:
            with open(p,"r",encoding="utf-8-sig") as f:
                for r in csv.DictReader(f):
                    rows.append({k.strip().upper().replace(" ","_"):v.strip() for k,v in r.items() if k})
        except Exception as e: print(f"    [WARN] {e}")
        return rows
    def _json(self,p):
        try:
            with open(p,"r",encoding="utf-8-sig") as f: return json.load(f)
        except Exception as e: print(f"    [WARN] {e}"); return None
