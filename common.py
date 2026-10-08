"""Shared helpers for the audit scripts."""
import json
import os
from dataclasses import asdict, dataclass

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    id: str
    severity: str
    service: str
    resource: str
    title: str
    detail: str
    remediation: str
    mitre: str = ""


class Collector:
    """Collects findings with sequential IDs such as IAM-001."""

    def __init__(self, prefix):
        self.prefix = prefix
        self.items = []

    def add(self, severity, resource, title, detail, remediation, mitre=""):
        fid = f"{self.prefix}-{len(self.items) + 1:03d}"
        self.items.append(
            Finding(fid, severity, self.prefix, resource, title, detail, remediation, mitre)
        )

    def sorted(self):
        """Return findings ordered by severity, renumbered so IDs follow that order."""
        ordered = sorted(self.items, key=lambda f: (SEV_ORDER[f.severity], f.title, f.resource))
        for n, f in enumerate(ordered, 1):
            f.id = f"{self.prefix}-{n:03d}"
        return ordered


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def print_summary(findings, title):
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f.severity] += 1
    print(f"\n=== {title}: {len(findings)} findings ===")
    print("  " + "  ".join(f"{s}={n}" for s, n in counts.items() if n or s != "INFO"))
    for f in findings:
        print(f"  [{f.severity:<8}] {f.id}  {f.title}\n             -> {f.resource}")


def write_outputs(findings, out_dir, name):
    """Write <name>_findings.json and <name>_findings.md into out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    jpath = os.path.join(out_dir, f"{name}_findings.json")
    with open(jpath, "w") as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2, default=str)

    mpath = os.path.join(out_dir, f"{name}_findings.md")
    with open(mpath, "w") as fh:
        fh.write(f"# {name.upper()} findings\n\n")
        fh.write("| ID | Severity | Resource | Title | MITRE | Remediation |\n")
        fh.write("|----|----------|----------|-------|-------|-------------|\n")
        for f in findings:
            row = [f.id, f.severity, f"`{f.resource}`", f.title, f.mitre, f.remediation]
            fh.write("| " + " | ".join(c.replace("|", "/") for c in row) + " |\n")
    return jpath, mpath
