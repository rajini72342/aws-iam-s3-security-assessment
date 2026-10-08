#!/usr/bin/env python3
"""compare_runs.py - before/after table from evidence/before and evidence/after."""
import argparse
import json
import os
from collections import Counter

SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def load(root, label):
    items = []
    for name in ("iam", "s3"):
        path = os.path.join(root, label, f"{name}_findings.json")
        if os.path.exists(path):
            with open(path) as fh:
                items += json.load(fh)
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default="evidence")
    args = ap.parse_args()

    before, after = load(args.evidence, "before"), load(args.evidence, "after")
    if not before:
        raise SystemExit("No evidence/before/*.json found - run run_assessment.sh before first.")

    cb, ca = Counter(f["severity"] for f in before), Counter(f["severity"] for f in after)
    print("| Severity | Before | After |\n|----------|--------|-------|")
    for s in SEVS:
        print(f"| {s} | {cb.get(s, 0)} | {ca.get(s, 0)} |")
    print(f"| **Total** | **{len(before)}** | **{len(after)}** |")

    tb, ta = Counter(f["title"] for f in before), Counter(f["title"] for f in after)
    print("\n### Findings resolved (by title)")
    for t in sorted(set(tb) - set(ta)):
        print(f"- {t} (x{tb[t]})")
    still = sorted(set(ta))
    if still:
        print("\n### Still present after remediation (document as accepted risk or fix)")
        for t in still:
            print(f"- {t} (x{ta[t]})")


if __name__ == "__main__":
    main()
