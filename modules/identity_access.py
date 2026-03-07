"""
Identity & Access Management Auditor
=======================================
SSPM Category: Identity Security
Checks: Dormant accounts, admin sprawl, orphaned users, privilege creep,
        SoD conflicts, group hygiene, terminated access, shared accounts
"""
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any
from modules.base import BaseAuditor

class IdentityAccessAuditor(BaseAuditor):
    ADMIN_GROUPS=["Customer Administrator","Full Access","System Admin","Super User",
                  "UserAdmin","IT Administrator","Procurement Admin"]
    SOD_CONFLICTS=[
        ("Requisition Creator","Requisition Approver","Create + approve own requisitions"),
        ("Purchase Order Creator","Purchase Order Approver","Create + approve own POs"),
        ("Invoice Reconciliation","Payment Processing","Reconcile + process own payments"),
        ("Supplier Manager","Contract Manager","Manage suppliers + contracts"),
        ("Catalog Manager","Purchase Order Creator","Manage catalogs + create POs"),
        ("Customer Administrator","Requisition Creator","Admin + transactional access"),
    ]

    def run_all_checks(self)->List[Dict]:
        self.check_dormant_accounts(); self.check_admin_sprawl()
        self.check_orphaned_users(); self.check_terminated_access()
        self.check_sod_conflicts(); self.check_shared_accounts()
        self.check_privilege_creep(); self.check_group_hygiene()
        return self.findings

    def check_dormant_accounts(self):
        users=self.data.get("users")
        if not users: return
        days=self.get_config("dormant_days",90); dormant=[]; now=datetime.now()
        for u in users:
            user=u.get("USERNAME",u.get("USER_ID",""))
            status=u.get("STATUS","").upper(); last=u.get("LAST_LOGIN","")
            if status in ("INACTIVE","DISABLED","LOCKED"): continue
            if last:
                for fmt in ("%Y-%m-%d","%m/%d/%Y","%d.%m.%Y"):
                    try:
                        d=datetime.strptime(last.strip(),fmt)
                        if (now-d).days>days: dormant.append(f"{user} (last login: {last}, {(now-d).days}d ago)")
                        break
                    except ValueError: continue
        if dormant:
            self.finding("IAM-001",f"Dormant accounts ({len(dormant)}, >{days}d inactive)",
                self.SEVERITY_MEDIUM,"Identity & Access",
                f"{len(dormant)} active accounts haven't logged in for {days}+ days.",dormant[:30],
                "Implement automated dormant account deactivation. Review with HR.",
                ["SAP Ariba Security Guide — User Lifecycle","SSPM — Inactive Identities"])

    def check_admin_sprawl(self):
        groups=self.data.get("user_groups") or []; roles=self.data.get("user_roles") or []
        admins=set()
        for r in groups+roles:
            user=r.get("USERNAME",r.get("USER_ID",""))
            grp=r.get("GROUP",r.get("GROUP_NAME",r.get("ROLE","")))
            if any(a.upper() in grp.upper() for a in self.ADMIN_GROUPS): admins.add(user)
        mx=self.get_config("max_admins",10)
        if len(admins)>mx:
            self.finding("IAM-002",f"Excessive admin accounts ({len(admins)}, max: {mx})",
                self.SEVERITY_HIGH,"Identity & Access",
                f"{len(admins)} users have admin-level group membership.",list(admins)[:20],
                "Restrict admin groups. Use delegated admin roles. Apply least privilege.",
                ["SAP Ariba — Admin Group Best Practices","SSPM — Overprivileged Accounts"])

    def check_orphaned_users(self):
        users=self.data.get("users"); groups=self.data.get("user_groups")
        if not users or not groups: return
        assigned=set(r.get("USERNAME",r.get("USER_ID","")).upper() for r in groups)
        orphaned=[u.get("USERNAME",u.get("USER_ID","")) for u in users
                 if u.get("STATUS","").upper() not in ("INACTIVE","DISABLED","TERMINATED")
                 and u.get("USERNAME",u.get("USER_ID","")).upper() not in assigned]
        if orphaned:
            self.finding("IAM-003",f"Users without group assignments ({len(orphaned)})",
                self.SEVERITY_MEDIUM,"Identity & Access",
                f"{len(orphaned)} active users have no group assignments.",orphaned[:20],
                "Assign appropriate groups or deactivate accounts.",
                ["SAP Ariba — User Group Management"])

    def check_terminated_access(self):
        users=self.data.get("users")
        if not users: return
        termed=[u.get("USERNAME","") for u in users
               if u.get("EMPLOYMENT_STATUS",u.get("EMP_STATUS","")).upper() in ("TERMINATED","SEPARATED","LEFT")
               and u.get("STATUS","").upper() in ("ACTIVE","ENABLED","")]
        if termed:
            self.finding("IAM-004","Terminated employees with active Ariba accounts",
                self.SEVERITY_CRITICAL,"Identity & Access",
                f"{len(termed)} terminated employees still have active accounts.",termed,
                "Implement automated deprovisioning on employment termination.",
                ["SAP Ariba — Offboarding Security","SSPM — Zombie Accounts"])

    def check_sod_conflicts(self):
        groups=self.data.get("user_groups") or []; roles=self.data.get("user_roles") or []
        user_groups=defaultdict(set)
        for r in groups+roles:
            u=r.get("USERNAME",r.get("USER_ID",""))
            g=r.get("GROUP",r.get("GROUP_NAME",r.get("ROLE","")))
            if u and g: user_groups[u].add(g.upper())
        conflicts=[]
        for a,b,risk in self.SOD_CONFLICTS:
            for user,grps in user_groups.items():
                has_a=any(a.upper() in g for g in grps)
                has_b=any(b.upper() in g for g in grps)
                if has_a and has_b: conflicts.append(f"{user}: {a} + {b} — {risk}")
        if conflicts:
            self.finding("IAM-005",f"Segregation of Duties conflicts ({len(conflicts)})",
                self.SEVERITY_CRITICAL,"Identity & Access",
                f"{len(conflicts)} SoD conflict(s) where users hold conflicting roles.",conflicts[:20],
                "Split conflicting roles. Implement compensating controls.",
                ["SAP Ariba — SoD Best Practices","SOX Section 404"])

    def check_shared_accounts(self):
        users=self.data.get("users")
        if not users: return
        shared=[u.get("USERNAME","") for u in users
               if any(kw in u.get("USERNAME","").upper()
                      for kw in ("SHARED","GENERIC","TEAM","SERVICE","TEST","DEMO"))]
        if shared:
            self.finding("IAM-006",f"Potential shared/generic accounts ({len(shared)})",
                self.SEVERITY_HIGH,"Identity & Access",
                "Shared accounts eliminate individual accountability.",shared,
                "Replace shared accounts with named user accounts. Use service accounts for integrations.",
                ["SAP Ariba Security — Individual Accountability"])

    def check_privilege_creep(self):
        groups=self.data.get("user_groups") or []
        user_count=defaultdict(int)
        for r in groups: user_count[r.get("USERNAME",r.get("USER_ID",""))]+=1
        excessive=[(u,c) for u,c in user_count.items() if c>self.get_config("max_groups_per_user",8)]
        if excessive:
            items=[f"{u}: {c} groups" for u,c in excessive[:20]]
            self.finding("IAM-007",f"Users with excessive group memberships ({len(excessive)})",
                self.SEVERITY_MEDIUM,"Identity & Access",
                "Users assigned to many groups may have accumulated unnecessary privileges.",items,
                "Review and remove unnecessary group memberships. Implement periodic access reviews.",
                ["SSPM — Privilege Creep Detection"])

    def check_group_hygiene(self):
        groups=self.data.get("user_groups") or []
        grp_members=defaultdict(int)
        for r in groups: grp_members[r.get("GROUP",r.get("GROUP_NAME",""))]+=1
        empty=[g for g,c in grp_members.items() if c==0]
        if not empty:
            # Check from roles data
            roles=self.data.get("roles") or []
            assigned_groups=set(r.get("GROUP",r.get("GROUP_NAME","")) for r in groups)
            all_groups=set(r.get("GROUP_NAME",r.get("NAME","")) for r in roles)
            empty=[g for g in all_groups-assigned_groups if g]
        if empty:
            self.finding("IAM-008",f"Empty/unused groups ({len(empty)})",
                self.SEVERITY_LOW,"Identity & Access",
                f"{len(empty)} group(s) have no members.",empty[:15],
                "Review and remove unused groups.",["SAP Ariba — Group Lifecycle"])
