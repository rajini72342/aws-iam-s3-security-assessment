#!/usr/bin/env python3
"""
audit_s3.py - read-only S3 misconfiguration audit.

Checks per bucket: Block Public Access, public bucket policy/ACL,
Principal '*' statements, default encryption, versioning, access logging.
Also checks the account-level Block Public Access setting.
"""
import argparse
import os
import sys

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(__file__))
from common import Collector, as_list, print_summary, write_outputs  # noqa: E402

PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers (anyone on the internet)",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers (any AWS account)",
}


def err_code(e):
    return e.response["Error"]["Code"]


def audit_bucket(s3, name, c):
    # 1. Block Public Access (bucket level)
    try:
        bpa = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        missing = [k for k, v in bpa.items() if not v]
        if missing:
            c.add("HIGH", name, "Block Public Access partially/fully disabled",
                  f"Disabled settings: {', '.join(missing)}.",
                  "Enable all four Block Public Access settings.", "T1530")
    except ClientError as e:
        if err_code(e) == "NoSuchPublicAccessBlockConfiguration":
            c.add("HIGH", name, "Block Public Access not configured",
                  "No bucket-level Block Public Access configuration.",
                  "Enable all four Block Public Access settings.", "T1530")
        else:
            raise

    # 2. Is the bucket public via policy? (AWS's own evaluation)
    try:
        if s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {}).get("IsPublic"):
            c.add("CRITICAL", name, "Bucket is PUBLIC via bucket policy",
                  "AWS evaluates the bucket policy as granting public access.",
                  "Remove public statements; use CloudFront OAC or presigned URLs if sharing is needed.", "T1530")
    except ClientError as e:
        if err_code(e) != "NoSuchBucketPolicy":
            raise

    # 3. Wildcard principals without conditions (explains *why*)
    try:
        import json
        policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
        for st in as_list(policy.get("Statement")):
            principal = st.get("Principal")
            is_star = principal == "*" or (isinstance(principal, dict) and "*" in as_list(principal.get("AWS")))
            if st.get("Effect") == "Allow" and is_star and not st.get("Condition"):
                acts = ", ".join(str(a) for a in as_list(st.get("Action")))
                c.add("CRITICAL", name, "Bucket policy grants access to Principal '*'",
                      f"Sid={st.get('Sid', '-')}, Actions: {acts}.",
                      "Restrict Principal to specific accounts/roles, or add strong conditions.", "T1530")
    except ClientError as e:
        if err_code(e) != "NoSuchBucketPolicy":
            raise

    # 4. ACL grants to public groups
    for grant in s3.get_bucket_acl(Bucket=name)["Grants"]:
        uri = grant["Grantee"].get("URI")
        if uri in PUBLIC_GRANTEES:
            c.add("CRITICAL", name, "Bucket ACL grants public access",
                  f"{PUBLIC_GRANTEES[uri]} has {grant['Permission']}.",
                  "Remove the grant and disable ACLs (BucketOwnerEnforced).", "T1530")

    # 5. Default encryption
    try:
        s3.get_bucket_encryption(Bucket=name)
    except ClientError as e:
        if err_code(e) == "ServerSideEncryptionConfigurationNotFoundError":
            c.add("MEDIUM", name, "Default encryption not configured",
                  "No explicit default encryption rule.", "Enable SSE-S3 or SSE-KMS default encryption.")
        else:
            raise

    # 6. Versioning
    if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
        c.add("LOW", name, "Versioning disabled",
              "Overwrites/deletes are unrecoverable and ransomware-prone.", "Enable versioning (add MFA delete if possible).")

    # 7. Access logging
    if "LoggingEnabled" not in s3.get_bucket_logging(Bucket=name):
        c.add("LOW", name, "Server access logging disabled",
              "No access logs for forensic investigation.", "Enable logging to a dedicated, locked-down bucket.")


def audit_account_bpa(session, account_id, c):
    s3c = session.client("s3control")
    try:
        cfg = s3c.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
        if not all(cfg.values()):
            c.add("MEDIUM", "account", "Account-level Block Public Access not fully enabled",
                  f"Settings: {cfg}", "Enable all four account-level settings once no bucket needs public access.")
    except ClientError as e:
        if err_code(e) == "NoSuchPublicAccessBlockConfiguration":
            c.add("MEDIUM", "account", "Account-level Block Public Access not configured",
                  "No account-level guardrail.", "Enable all four account-level settings.")
        else:
            raise


def audit(session, prefix=""):
    s3 = session.client("s3")
    account_id = session.client("sts").get_caller_identity()["Account"]
    c = Collector("S3")
    audit_account_bpa(session, account_id, c)
    for b in s3.list_buckets()["Buckets"]:
        if not b["Name"].startswith(prefix):
            continue
        try:
            audit_bucket(s3, b["Name"], c)
        except ClientError as e:
            c.add("INFO", b["Name"], "Could not fully audit bucket", f"{err_code(e)}", "Check permissions/region.")
    return c.sorted()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile")
    ap.add_argument("--label", default="before")
    ap.add_argument("--out", default="evidence")
    ap.add_argument("--prefix", default="", help="only audit buckets whose name starts with this (e.g. iamlab-)")
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile)
    findings = audit(session, args.prefix)
    print_summary(findings, "S3 audit")
    j, m = write_outputs(findings, os.path.join(args.out, args.label), "s3")
    print(f"\nSaved {j}\n      {m}")


if __name__ == "__main__":
    main()
