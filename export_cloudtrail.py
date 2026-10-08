#!/usr/bin/env python3
"""
export_cloudtrail.py - dump CloudTrail *event history* (free, last 90 days of
management events) to JSON Lines so you can analyse it offline or load it into Splunk.

IAM and console sign-in events are logged in us-east-1; S3 bucket-level
management events are logged in the bucket's region. Export both.
Events can take ~15 minutes to appear.
"""
import argparse
import json
import os
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile")
    ap.add_argument("--regions", nargs="+", default=["us-east-1", "ap-south-1"])
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--out", default="evidence/cloudtrail/events.jsonl")
    args = ap.parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    cfg = Config(retries={"max_attempts": 10, "mode": "adaptive"})

    total = 0
    with open(args.out, "w") as fh:
        for region in args.regions:
            ct = boto3.Session(profile_name=args.profile, region_name=region).client("cloudtrail", config=cfg)
            for page in ct.get_paginator("lookup_events").paginate(StartTime=start, EndTime=end):
                for ev in page["Events"]:
                    fh.write(json.dumps(json.loads(ev["CloudTrailEvent"])) + "\n")
                    total += 1
            print(f"{region}: done")
    print(f"Wrote {total} events to {args.out}")


if __name__ == "__main__":
    main()
