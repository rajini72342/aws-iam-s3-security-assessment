# aws-iam-s3-security-assessment
Assessed a misconfigured AWS environment (IAM and S3) with Prowler, Checkov and custom boto3 scripts; found [N] issues ([X] critical) and remediated to least privilege with Terraform ([N] → [M] findings). Built CloudTrail detections in Splunk SPL and Sigma, mapped to MITRE ATT&amp;CK, for the same misconfigurations.

AWS IAM & S3 Security Assessment
> Take a misconfigured cloud environment, find over-permissioned identities and
> public storage, write the remediation, and build detections for the same
> mistakes. Everything runs on a free-tier AWS account (or fully offline).
Role targeted: Entry-level SOC Analyst / Cloud Security / IAM
Skills shown: cloud security, IAM least privilege, misconfiguration hunting,
IaC scanning, CloudTrail log analysis, detection engineering (Splunk SPL + Sigma),
security reporting.
---
What this project does
Deploys a deliberately vulnerable AWS lab with Terraform
(public S3 bucket, admin users, wildcard policies, open role trust, weak password policy).
Assesses it three ways: IaC scan (Checkov), live-account scan (Prowler + two custom boto3 audit scripts), and IAM Access Analyzer.
Documents every finding with severity, evidence, MITRE ATT&CK mapping and fix.
Remediates with a second Terraform stack that follows least privilege, then re-scans and compares before vs after.
Detects: exports CloudTrail events and runs detections for the same
misconfigurations (Python, Splunk SPL, Sigma rules).
Architecture
```
            terraform/vulnerable                  terraform/remediated
                    |                                      |
                    v                                      v
   +-------------- AWS free-tier account ------------------------------+
   |  S3: public bucket, backups bucket     IAM: admin user, wildcard   |
   |  IAM: ec2 admin role, open-trust role  user, weak password policy  |
   +------+-----------------------+--------------------------+---------+
          |                       |                          |
   Checkov (IaC)        audit\_iam.py / audit\_s3.py       CloudTrail
   Prowler (live)       IAM Access Analyzer              (event history)
          |                       |                          |
          +-----------+-----------+                          v
                      v                          export\_cloudtrail.py
        evidence/before + evidence/after         detect\_cloudtrail.py
                      |                          detections/\*.spl, sigma/
                      v
              compare\_runs.py -> report/REPORT\_TEMPLATE.md
```
Repo layout
```
terraform/vulnerable/    # the broken environment (intentional!)
terraform/remediated/    # the fixed environment
scripts/
  audit\_iam.py           # IAM checks via boto3
  audit\_s3.py            # S3 checks via boto3
  run\_assessment.sh      # runs Checkov + Prowler + audits -> evidence/<label>/
  compare\_runs.py        # before vs after table
  export\_cloudtrail.py   # CloudTrail event history -> JSONL
  detect\_cloudtrail.py   # offline detections over the JSONL
  cleanup.sh             # destroy everything
detections/
  splunk\_cloudtrail.spl  # 8 SPL searches
  sigma/\*.yml            # 3 Sigma rules
docs/
  SETUP.md               # step-by-step walkthrough (start here)
  EXPECTED\_FINDINGS.md   # misconfig -> detection -> fix -> MITRE
  INTERVIEW\_NOTES.md     # how to talk about this project
report/REPORT\_TEMPLATE.md
```
Quick start
Read `docs/SETUP.md` first. The short version:
```bash
python3 -m venv .venv \&\& source .venv/bin/activate
pip install -r requirements.txt \&\& pipx install prowler

cd terraform/vulnerable \&\& terraform init \&\& terraform apply   # deploy lab
cd ../..
./scripts/run\_assessment.sh before iamlab                       # scan

# ... exploit demo, CloudTrail export, detections (see SETUP.md) ...

cd terraform/vulnerable \&\& terraform destroy \&\& cd ../remediated
terraform init \&\& terraform apply                               # fix
cd ../.. \&\& ./scripts/run\_assessment.sh after iamlab
python3 scripts/compare\_runs.py                                 # before/after
./scripts/cleanup.sh                                            # leave no trace (and no bill)
```


Safety and ethics
Only run this in your own AWS account. Use fake data only.
The vulnerable stack contains one role whose trust policy allows any AWS principal. It has no permissions attached; never attach any.
Set a $1 budget alert before deploying, and run `scripts/cleanup.sh` when done.
Never commit credentials, `.tfstate` 
