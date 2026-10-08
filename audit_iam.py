#!/usr/bin/env python3
"""
audit_iam.py - read-only IAM misconfiguration audit.

Checks:
  * root account: MFA missing, access keys present
  * users: AdministratorAccess, wildcard / privilege-escalation policies,
           console access without MFA, old or unused access keys
  * roles: AdministratorAccess, wildcard policies, open or weak trust policies
  * account password policy strength

Needs only read permissions (SecurityAudit managed policy is enough).
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(__file__))
from common import Collector, as_list, print_summary, write_outputs  # noqa: E402

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

# Actions that let a principal grant itself more power (classic IAM privesc paths)
PRIVESC = {
    "iam:passrole",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:attachgrouppolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:putgrouppolicy",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:updateassumerolepolicy",
    "iam:addusertogroup",
}


def analyze_policy(doc, resource, source, c):
    """Flag dangerous Allow statements inside one policy document."""
    for st in as_list(doc.get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        actions = [str(a).lower() for a in as_list(st.get("Action"))]
        resources = [str(r) for r in as_list(st.get("Resource"))]
        wide = "*" in resources

        if "*" in actions and wide:
            c.add("CRITICAL", resource, "Policy allows all actions on all resources",
                  f"{source}: Action '*' on Resource '*' (equivalent to admin).",
                  "Replace with specific actions scoped to specific resource ARNs.", "T1078.004")
            continue
        if not wide:
            continue
        svc = sorted(a for a in actions if a.endswith(":*"))
        if svc:
            c.add("HIGH", resource, "Service-wide wildcard on all resources",
                  f"{source}: {', '.join(svc)} on Resource '*'.",
                  "List only the needed actions and restrict Resource to specific ARNs.", "T1078.004")
        risky = sorted(a for a in actions if a in PRIVESC)
        if risky:
            c.add("HIGH", resource, "Privilege-escalation actions allowed on all resources",
                  f"{source}: {', '.join(risky)} on Resource '*'.",
                  "Remove, or scope to specific ARNs with conditions; add permission boundaries.",
                  "T1098")


def managed_policy_doc(iam, arn):
    version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    return iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]


def audit_attached(iam, attached, resource, kind, c):
    for pol in attached:
        arn = pol["PolicyArn"]
        if arn == ADMIN_ARN:
            c.add("CRITICAL", resource, f"AdministratorAccess attached to {kind}",
                  f"{kind.capitalize()} has the AWS-managed AdministratorAccess policy.",
                  "Grant only the permissions the workload needs; reserve admin for break-glass roles with MFA.",
                  "T1078.004")
            continue
        try:
            analyze_policy(managed_policy_doc(iam, arn), resource, f"managed policy {pol['PolicyName']}", c)
        except ClientError:
            pass


def audit_account(iam, c):
    summary = iam.get_account_summary()["SummaryMap"]
    if not summary.get("AccountMFAEnabled"):
        c.add("CRITICAL", "root", "Root account has no MFA",
              "AccountMFAEnabled = 0.", "Enable hardware or virtual MFA on the root user.", "T1078.004")
    if summary.get("AccountAccessKeysPresent"):
        c.add("CRITICAL", "root", "Root account has access keys",
              "Root keys exist.", "Delete root access keys; use IAM roles/users.", "T1078.004")

    try:
        pp = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            c.add("HIGH", "account", "No account password policy set",
                  "AWS defaults apply (weak).", "Create a policy: min 14 chars, complexity, 90-day rotation.")
            return
        raise
    problems = []
    if pp.get("MinimumPasswordLength", 0) < 14:
        problems.append(f"min length {pp.get('MinimumPasswordLength')} (<14)")
    for key, label in [("RequireUppercaseCharacters", "uppercase"), ("RequireLowercaseCharacters", "lowercase"),
                       ("RequireNumbers", "numbers"), ("RequireSymbols", "symbols")]:
        if not pp.get(key):
            problems.append(f"{label} not required")
    if not pp.get("MaxPasswordAge"):
        problems.append("no password expiry")
    if not pp.get("PasswordReusePrevention"):
        problems.append("no reuse prevention")
    if problems:
        c.add("MEDIUM", "account", "Weak account password policy", "; ".join(problems),
              "Set min length >= 14, require all character classes, expire at 90 days, prevent reuse.")


def audit_users(iam, c, max_age_days):
    now = datetime.now(timezone.utc)
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name, res = user["UserName"], user["UserName"]

            audit_attached(iam, iam.list_attached_user_policies(UserName=name)["AttachedPolicies"],
                           res, "user", c)
            for pname in iam.list_user_policies(UserName=name)["PolicyNames"]:
                doc = iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"]
                analyze_policy(doc, res, f"inline policy {pname}", c)
            for grp in iam.list_groups_for_user(UserName=name)["Groups"]:
                audit_attached(iam, iam.list_attached_group_policies(GroupName=grp["GroupName"])["AttachedPolicies"],
                               f"{res} (via group {grp['GroupName']})", "group", c)

            has_console = True
            try:
                iam.get_login_profile(UserName=name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    has_console = False
                else:
                    raise
            has_mfa = bool(iam.list_mfa_devices(UserName=name)["MFADevices"])
            if has_console and not has_mfa:
                c.add("HIGH", res, "Console user without MFA",
                      "User can sign in with a password and has no MFA device.",
                      "Enforce MFA (require-MFA deny policy) and register a device.", "T1078.004")

            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue
                masked = "..." + key["AccessKeyId"][-4:]
                age = (now - key["CreateDate"]).days
                last = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"]
                last_date = last.get("LastUsedDate")
                if age > max_age_days:
                    c.add("MEDIUM", f"{res}/{masked}", "Access key older than rotation limit",
                          f"Key is {age} days old (limit {max_age_days}).", "Rotate or delete the key.", "T1098.001")
                if last_date is None and age > max_age_days:
                    c.add("MEDIUM", f"{res}/{masked}", "Active access key never used",
                          "Key has never been used.", "Delete unused keys.", "T1098.001")
                elif last_date is not None and (now - last_date).days > max_age_days:
                    c.add("MEDIUM", f"{res}/{masked}", "Active access key unused for a long time",
                          f"Last used {(now - last_date).days} days ago.", "Deactivate and delete stale keys.",
                          "T1098.001")


def audit_trust(role, account_id, c):
    name = role["RoleName"]
    for st in as_list(role["AssumeRolePolicyDocument"].get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal", {})
        aws_p = ["*"] if principal == "*" else [str(p) for p in as_list(principal.get("AWS"))]
        cond = st.get("Condition")
        if "*" in aws_p:
            if not cond:
                c.add("CRITICAL", name, "Role trust policy allows any AWS principal",
                      "Principal '*' with no Condition: any AWS account can attempt to assume this role.",
                      "Trust only specific account/role ARNs; add ExternalId or MFA conditions.", "T1078.004")
            else:
                c.add("MEDIUM", name, "Role trust uses wildcard principal with a condition",
                      f"Condition: {json.dumps(cond)}", "Verify the condition is strong enough; prefer explicit ARNs.",
                      "T1078.004")
        for p in aws_p:
            if p == "*":
                continue
            acct = p.split(":")[4] if p.startswith("arn:") and len(p.split(":")) > 4 else p
            if acct.isdigit() and acct != account_id and "ExternalId" not in json.dumps(cond or {}):
                c.add("MEDIUM", name, "Cross-account trust without ExternalId",
                      f"Trusts account {acct} without sts:ExternalId.",
                      "Require sts:ExternalId (confused-deputy protection).", "T1078.004")


def audit_roles(iam, account_id, c):
    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            if role["Path"].startswith("/aws-service-role/") or role["RoleName"].startswith("AWSServiceRole"):
                continue
            name = role["RoleName"]
            audit_trust(role, account_id, c)
            audit_attached(iam, iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"], name, "role", c)
            for pname in iam.list_role_policies(RoleName=name)["PolicyNames"]:
                doc = iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]
                analyze_policy(doc, name, f"inline policy {pname}", c)


def audit(session, max_age_days=90):
    iam = session.client("iam")
    account_id = session.client("sts").get_caller_identity()["Account"]
    c = Collector("IAM")
    audit_account(iam, c)
    audit_users(iam, c, max_age_days)
    audit_roles(iam, account_id, c)
    return c.sorted()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", help="AWS CLI profile (default: environment / AWS_PROFILE)")
    ap.add_argument("--label", default="before", help="evidence label: before | after")
    ap.add_argument("--out", default="evidence", help="evidence root directory")
    ap.add_argument("--max-key-age-days", type=int, default=90)
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile)
    findings = audit(session, args.max_key_age_days)
    print_summary(findings, "IAM audit")
    j, m = write_outputs(findings, os.path.join(args.out, args.label), "iam")
    print(f"\nSaved {j}\n      {m}")


if __name__ == "__main__":
    main()
