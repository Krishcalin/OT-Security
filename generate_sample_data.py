#!/usr/bin/env python3
"""Generate sample SAP Ariba configuration data with deliberate security issues."""
import json, csv, os

SD = "sample_data"
os.makedirs(SD, exist_ok=True)

# ── Users CSV ──
with open(f"{SD}/users.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["USERNAME","DISPLAY_NAME","EMAIL","STATUS","LAST_LOGIN","EMPLOYMENT_STATUS","DEPARTMENT","CREATED_DATE"])
    w.writerow(["admin","System Admin","admin@corp.com","Active","2026-03-06","Active","IT","2020-01-15"])
    w.writerow(["jsmith","John Smith","john.smith@corp.com","Active","2026-03-05","Active","Procurement","2021-03-20"])
    w.writerow(["mwilson","Mary Wilson","mary.wilson@corp.com","Active","2025-09-14","Active","Finance","2022-01-10"])
    w.writerow(["rjones","Robert Jones","robert.jones@corp.com","Active","2025-06-01","Active","Procurement","2021-06-15"])
    w.writerow(["ldavis","Lisa Davis","lisa.davis@corp.com","Active","2024-11-20","Active","Supply Chain","2020-09-01"])
    w.writerow(["shared_procurement","Shared Procurement","proc-team@corp.com","Active","2026-03-04","Active","Procurement","2019-05-01"])
    w.writerow(["generic_ap","AP Team","ap-team@corp.com","Active","2026-03-01","Active","Finance","2020-02-01"])
    w.writerow(["test_user","Test Account","test@corp.com","Active","2024-01-15","Active","IT","2023-01-01"])
    w.writerow(["demo_buyer","Demo Buyer","demo@corp.com","Active","2023-06-01","Active","IT","2023-01-01"])
    w.writerow(["kbrown","Kevin Brown","kevin.brown@corp.com","Active","2026-03-06","Terminated","Procurement","2021-04-10"])
    w.writerow(["agarcia","Ana Garcia","ana.garcia@corp.com","Active","2026-02-28","Separated","Finance","2022-08-01"])
    w.writerow(["tlee","Tom Lee","tom.lee@corp.com","Active","2025-12-01","Active","Procurement","2022-05-20"])
    w.writerow(["pwang","Priya Wang","priya.wang@corp.com","Active","2026-03-06","Active","IT","2023-01-15"])
    w.writerow(["service_api","API Service","api@corp.com","Active","2026-03-06","Active","IT","2021-01-01"])
    w.writerow(["orphan_user","Orphan User","orphan@corp.com","Active","2026-01-10","Active","Unknown","2024-06-01"])

# ── User Groups CSV ──
with open(f"{SD}/user_groups.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["USERNAME","GROUP","ASSIGNED_DATE"])
    w.writerow(["admin","Customer Administrator","2020-01-15"])
    w.writerow(["admin","Full Access","2020-01-15"])
    w.writerow(["admin","Requisition Creator","2020-01-15"])
    w.writerow(["admin","Requisition Approver","2020-01-15"])
    w.writerow(["admin","Purchase Order Creator","2020-01-15"])
    w.writerow(["admin","Purchase Order Approver","2020-01-15"])
    w.writerow(["admin","Invoice Reconciliation","2020-01-15"])
    w.writerow(["admin","Payment Processing","2020-01-15"])
    w.writerow(["admin","Supplier Manager","2020-02-01"])
    w.writerow(["admin","Contract Manager","2020-02-01"])
    w.writerow(["jsmith","Requisition Creator","2021-03-20"])
    w.writerow(["jsmith","Requisition Approver","2021-05-01"])  # SoD conflict
    w.writerow(["jsmith","Purchase Order Creator","2021-07-01"])
    w.writerow(["jsmith","Purchase Order Approver","2022-01-15"])  # SoD conflict
    w.writerow(["jsmith","Catalog Manager","2022-03-01"])
    w.writerow(["mwilson","Invoice Reconciliation","2022-01-10"])
    w.writerow(["mwilson","Payment Processing","2022-01-10"])  # SoD conflict
    w.writerow(["rjones","Requisition Creator","2021-06-15"])
    w.writerow(["rjones","Supplier Manager","2021-08-01"])
    w.writerow(["rjones","Contract Manager","2022-02-01"])  # SoD conflict
    w.writerow(["ldavis","Requisition Creator","2020-09-01"])
    w.writerow(["shared_procurement","Requisition Creator","2019-05-01"])
    w.writerow(["generic_ap","Invoice Reconciliation","2020-02-01"])
    w.writerow(["tlee","Requisition Creator","2022-05-20"])
    w.writerow(["pwang","Customer Administrator","2023-01-15"])
    w.writerow(["pwang","Full Access","2023-01-15"])
    w.writerow(["pwang","System Admin","2023-02-01"])
    w.writerow(["kbrown","Requisition Creator","2021-04-10"])  # Terminated but still in group
    w.writerow(["agarcia","Invoice Reconciliation","2022-08-01"])  # Separated but still in group

# ── SSO Configuration ──
json.dump({
    "ssoEnabled": False,
    "samlVersion": "2.0",
    "idpEntityId": "https://idp.corp.com",
    "signedAssertions": True,
    "encryptedAssertions": False,
    "allowIdpInitiated": True,
    "enforceSSO": False,
    "sessionTimeout": 60,
    "sloEnabled": False,
    "nameIdFormat": "email"
}, open(f"{SD}/sso_config.json", "w"), indent=2)

# ── MFA Configuration ──
json.dump({
    "enabled": False,
    "adminMfa": False,
    "allowBypass": True,
    "methods": ["TOTP", "SMS", "Email"],
    "gracePeriodDays": 30,
    "rememberedDeviceDays": 90
}, open(f"{SD}/mfa_config.json", "w"), indent=2)

# ── Password Policy ──
json.dump({
    "minLength": 6,
    "requireUppercase": True,
    "requireDigit": True,
    "requireSpecial": False,
    "maxAge": 180,
    "historyCount": 3,
    "lockoutThreshold": 10,
    "lockoutDuration": 5
}, open(f"{SD}/password_policy.json", "w"), indent=2)

# ── API Clients ──
json.dump({"clients": [
    {"clientId": "erp-integration", "name": "ERP Sync", "scopes": ["procurement.read", "procurement.write"],
     "grantTypes": ["client_credentials"], "lastUsed": "2026-03-06", "created": "2021-06-01"},
    {"clientId": "legacy-app", "name": "Legacy Portal", "scopes": ["*"],
     "grantTypes": ["password", "client_credentials"], "lastUsed": "2025-04-10", "created": "2019-03-01"},
    {"clientId": "reporting-tool", "name": "Analytics", "scopes": ["reporting.read", "admin.full"],
     "grantTypes": ["authorization_code"], "lastUsed": "2026-03-05", "created": "2022-09-01"},
    {"clientId": "mobile-app", "name": "Mobile Buyer", "scopes": ["procurement.read"],
     "grantTypes": ["implicit"], "lastUsed": "2026-02-20", "created": "2023-01-15"},
    {"clientId": "old-connector", "name": "Retired Connector", "scopes": ["supplier.read", "supplier.write"],
     "grantTypes": ["client_credentials"], "lastUsed": "2024-08-15", "created": "2020-01-01"},
]}, open(f"{SD}/api_clients.json", "w"), indent=2)

# ── API Permissions CSV ──
with open(f"{SD}/api_permissions.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["CLIENT","ENTITY","ACCESS"])
    w.writerow(["erp-integration","PURCHASE_ORDER","WRITE"])
    w.writerow(["erp-integration","INVOICE","WRITE"])
    w.writerow(["legacy-app","SUPPLIER","FULL"])
    w.writerow(["legacy-app","PAYMENT","WRITE"])
    w.writerow(["legacy-app","USER","ADMIN"])
    w.writerow(["reporting-tool","REPORTING","READ"])
    w.writerow(["reporting-tool","CONTRACT","READ"])
    w.writerow(["mobile-app","REQUISITION","READ"])

# ── Integration Config ──
json.dump({
    "integrations": [
        {"name": "S4HANA-Cloud", "type": "CIG", "auth": "oauth2", "status": "active"},
        {"name": "Legacy-ERP", "type": "file", "auth": "", "status": "active"},
        {"name": "Travel-System", "type": "API", "auth": "basic", "status": "active"},
        {"name": "Old-Middleware", "type": "SOAP", "auth": "none", "status": "active"},
    ],
    "webhooks": [
        {"name": "PO-Notification", "url": "https://api.corp.com/po-hook", "secret": "configured"},
        {"name": "Invoice-Alert", "url": "http://legacy.corp.com:8080/invoice-hook", "secret": ""},
    ],
    "rateLimiting": None
}, open(f"{SD}/integration_config.json", "w"), indent=2)

# ── Approval Workflows ──
json.dump({
    "rules": [
        {"name": "PO-Under-1000", "threshold": 1000, "approvalRequired": False, "autoApprove": True},
        {"name": "PO-1000-to-10000", "threshold": 10000, "approvalRequired": True, "autoApprove": False, "approvers": 1},
        {"name": "PO-Above-10000", "threshold": 50000, "approvalRequired": True, "autoApprove": False, "approvers": 2},
        {"name": "Non-Catalog-Purchase", "threshold": 500, "approvalRequired": True, "autoApprove": True},
        {"name": "Contract-Renewal", "threshold": 100000, "approvalRequired": True, "autoApprove": False, "approvers": 3},
    ]
}, open(f"{SD}/approval_workflows.json", "w"), indent=2)

# ── Procurement Policies ──
json.dump({
    "thresholds": {"poAutoApproveLimit": 25000, "invoiceAutoPostLimit": 5000},
    "allowMaverickSpend": True,
    "requirePreApproval": False,
    "bulkExportEnabled": True,
    "retroactivePOAllowed": True,
    "punchoutRestrictions": False
}, open(f"{SD}/procurement_policies.json", "w"), indent=2)

# ── Supplier Config ──
json.dump({
    "onboarding": {
        "approvalRequired": False,
        "dueDiligence": False,
        "riskAssessment": False,
        "selfRegistration": True,
        "selfRegApproval": False,
        "sanctionsScreening": True
    },
    "authentication": {"mfaRequired": False, "passwordPolicy": "basic"},
    "dataValidation": {"bankDetailVerification": False, "taxIdVerification": True},
    "continuousMonitoring": False,
    "supplierSelfService": {"enabled": True, "viewOtherSuppliers": True, "editBankDetails": True}
}, open(f"{SD}/supplier_config.json", "w"), indent=2)

# ── Data Sharing ──
json.dump({
    "externalSharing": [
        {"name": "Partner-Reports", "scope": "APPROVED_PARTNERS", "entities": ["PO", "Invoice"]},
        {"name": "Public-Catalog", "scope": "ALL", "entities": ["Catalog"]},
        {"name": "Supplier-Portal", "scope": "ALL", "entities": ["Contract", "PO", "RFP"]},
    ]
}, open(f"{SD}/data_sharing.json", "w"), indent=2)

# ── Audit Config ──
json.dump({
    "enabled": True,
    "loggedEvents": ["user_login", "config_change", "po_create", "po_approve"],
    "retentionDays": 180,
    "siemExport": False,
    "alertOnAdminActions": False
}, open(f"{SD}/audit_config.json", "w"), indent=2)

# ── Encryption / Certificate Config ──
json.dump({
    "fieldLevelEncryption": False,
    "minTlsVersion": "tls1.1",
    "certificates": [
        {"name": "SAML-Signing", "expiryDate": "2025-06-15", "type": "X.509", "purpose": "SSO"},
        {"name": "API-TLS", "expiryDate": "2027-12-31", "type": "X.509", "purpose": "API"},
        {"name": "Legacy-Cert", "expiryDate": "2024-03-01", "type": "X.509", "purpose": "Integration"},
    ]
}, open(f"{SD}/encryption_config.json", "w"), indent=2)

# ── IP Restrictions ──
json.dump({
    "enabled": False,
    "allowedRanges": [],
    "adminRestricted": False
}, open(f"{SD}/ip_restrictions.json", "w"), indent=2)

# ── Compliance Config ──
json.dump({
    "frameworks": [],
    "retentionPolicies": [],
    "dataClassification": {"enabled": False}
}, open(f"{SD}/compliance_config.json", "w"), indent=2)

# ── Notification Config ──
json.dump({
    "securityAlerts": [],
    "channels": [],
    "escalationEnabled": False
}, open(f"{SD}/notification_config.json", "w"), indent=2)

# ── Custom Fields CSV ──
with open(f"{SD}/custom_fields.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["FIELD_NAME","ENTITY","TYPE","CLASSIFICATION","MASKED"])
    w.writerow(["VENDOR_TAX_ID","Supplier","Text","","No"])
    w.writerow(["BANK_ACCOUNT_NUM","Supplier","Text","","No"])
    w.writerow(["CONTACT_SSN","Supplier","Text","","No"])
    w.writerow(["ROUTING_NUMBER","Supplier","Text","","No"])
    w.writerow(["EMPLOYEE_EMAIL","User","Text","PII","No"])
    w.writerow(["BUDGET_CODE","Requisition","Text","","No"])

# ── Contract Config ──
json.dump({
    "expiryAlerts": False,
    "dualApproval": False,
    "allowNoCompete": True,
    "maxContractValue": 5000000,
    "autoRenewalDefault": True
}, open(f"{SD}/contract_config.json", "w"), indent=2)

# ── Catalog Config ──
json.dump({
    "approvalRequired": False,
    "punchoutEnabled": True,
    "priceVarianceThreshold": 0,
    "catalogUpdateNotification": False
}, open(f"{SD}/catalog_config.json", "w"), indent=2)

# ── Payment Config ──
json.dump({
    "threeWayMatch": False,
    "duplicateCheck": True,
    "autoPayEnabled": True,
    "autoPayApproval": False,
    "paymentHoldThreshold": 50000
}, open(f"{SD}/payment_config.json", "w"), indent=2)

# ── Network Config ──
json.dump({
    "publicProfileEnabled": True,
    "autoShareDocuments": True,
    "networkMembership": "open",
    "allowDirectMessaging": True
}, open(f"{SD}/network_config.json", "w"), indent=2)

# ── SoD Rules ──
json.dump({
    "enabled": False,
    "rules": [],
    "enforcementMode": "monitor"
}, open(f"{SD}/sod_rules.json", "w"), indent=2)

print(f"Generated {len(os.listdir(SD))} sample data files in {SD}/")
