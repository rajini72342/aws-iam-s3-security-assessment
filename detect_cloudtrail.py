#!/usr/bin/env python3
"""
detect_cloudtrail.py - run the project's detections over exported CloudTrail JSONL.
Mirrors detections/splunk_cloudtrail.spl so you can test logic without Splunk.

Usage: python3 scripts/detect_cloudtrail.py evidence/cloudtrail/events.jsonl
"""
import json
import sys


def g(event, path, default=None):
    """Dotted-path getter: g(e, 'userIdentity.arn')."""
    cur = event
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur


def actor_name(e):
    arn = g(e, "userIdentity.arn", "") or ""
    return arn.rsplit("/", 1)[-1]


RULES = [
    ("CT-001", "HIGH", "S3 bucket exposure change (policy/ACL/Block Public Access)", "T1530",
     lambda e: g(e, "eventSource") == "s3.amazonaws.com"
     and g(e, "eventName") in {"PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy",
                               "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock"}),
    ("CT-002", "HIGH", "Console login success WITHOUT MFA", "T1078.004",
     lambda e: g(e, "eventName") == "ConsoleLogin"
     and g(e, "responseElements.ConsoleLogin") == "Success"
     and g(e, "additionalEventData.MFAUsed") == "No"),
    ("CT-003", "CRITICAL", "AdministratorAccess attached to an identity", "T1098",
     lambda e: g(e, "eventName") in {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}
     and str(g(e, "requestParameters.policyArn", "")).endswith("/AdministratorAccess")),
    ("CT-004", "HIGH", "Inline policy or policy version changed", "T1098",
     lambda e: g(e, "eventName") in {"PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
                                     "CreatePolicyVersion", "SetDefaultPolicyVersion"}),
    ("CT-005", "HIGH", "Access key created for ANOTHER user (or by root)", "T1098.001",
     lambda e: g(e, "eventName") == "CreateAccessKey"
     and (g(e, "userIdentity.type") == "Root"
          or (g(e, "requestParameters.userName") or actor_name(e)) != actor_name(e))),
    ("CT-006", "CRITICAL", "CloudTrail logging stopped/modified/deleted", "T1562.008",
     lambda e: g(e, "eventSource") == "cloudtrail.amazonaws.com"
     and g(e, "eventName") in {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}),
    ("CT-007", "CRITICAL", "Root account activity", "T1078.004",
     lambda e: g(e, "userIdentity.type") == "Root" and g(e, "eventType") != "AwsServiceEvent"),
    ("CT-008", "HIGH", "Role trust policy modified", "T1098",
     lambda e: g(e, "eventName") == "UpdateAssumeRolePolicy"),
]


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    hits = []
    with open(sys.argv[1]) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            if g(ev, "errorCode"):  # skip failed calls (still interesting, but noisy)
                continue
            for rid, sev, title, mitre, test in RULES:
                if test(ev):
                    hits.append((g(ev, "eventTime", ""), rid, sev, title, mitre,
                                 g(ev, "userIdentity.arn", g(ev, "userIdentity.type", "?")),
                                 g(ev, "eventName"), g(ev, "sourceIPAddress", "?")))
    hits.sort()
    print(f"{len(hits)} detection hit(s)\n")
    for t, rid, sev, title, mitre, who, name, ip in hits:
        print(f"{t}  [{sev:<8}] {rid} {title}\n    actor={who}  event={name}  ip={ip}  mitre={mitre}")


if __name__ == "__main__":
    main()
