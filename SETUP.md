# Step-by-step walkthrough

Budget about 3-4 weekends. Everything here is free if you follow the safety steps.

## 0. Install prerequisites
* Python 3.10+, Git
* [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
* [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
* (Optional) Splunk Free / trial for the SPL detections

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pipx install prowler            # live-account scanner
```

## 1. AWS account safety (do this BEFORE deploying anything)
1. Create a new AWS account. Check the current free-tier / free-plan terms on the AWS Free Tier page first, because they change.
2. Sign in as root **once**: enable **MFA on root**, then stop using root.
3. Billing > **Budgets** > create a budget with a **$1** alert to your email.
4. IAM > create an admin user for yourself (e.g. `lab-operator`) with MFA. Create an access key for the CLI.
5. Configure a named profile (the keys live in `~/.aws/credentials`, never in the repo):
   ```bash
   aws configure --profile iamlab      # region: ap-south-1
   aws sts get-caller-identity --profile iamlab
   ```
6. S3 console > **Block Public Access settings for this account**. If all four are ON, the vulnerable bucket
   policy will be rejected (`AccessDenied` on `PutBucketPolicy`). For the lab only, turn them OFF, and turn
   them back ON after cleanup.

> No account yet / no card? Do Phase A only: run `checkov -d terraform/vulnerable` and
> `checkov -d terraform/remediated`, read `docs/EXPECTED_FINDINGS.md`, and write the report from the Checkov output.

## 2. Deploy the vulnerable lab
```bash
export AWS_PROFILE=iamlab
cd terraform/vulnerable
terraform init
terraform plan          # read it: this is your "before" architecture
terraform apply         # type 'yes'
terraform output
cd ../..
```
Screenshot the `terraform output` and the S3 console.

## 3. "Before" assessment
```bash
./scripts/run_assessment.sh before iamlab
```
Also capture manually (screenshots go in `evidence/before/`):
* **IAM Access Analyzer** > Findings (shows the public bucket and the open-trust role)
* **IAM > Credential report** > download CSV
* **S3 console** showing the "Publicly accessible" badge

## 4. Prove the risk (your own lab bucket only)
The public bucket needs no credentials:
```bash
BUCKET=$(cd terraform/vulnerable && terraform output -raw public_bucket)
aws s3 ls "s3://$BUCKET" --no-sign-request
curl "https://$BUCKET.s3.ap-south-1.amazonaws.com/fake-passwords.txt"
```
Note the contents, then think about it as a SOC analyst: *who could find this, and what would the logs show?*

Optional, read-only reasoning exercise: for `dev-wildcard`, write down how `iam:AttachUserPolicy` on `*` lets the user
grant themselves AdministratorAccess. Do not run it; describing the path is enough. (flaws.cloud / flaws2.cloud are the right places to practise hands-on exploitation.)

## 5. Generate log activity, then export it
Make some "attacker-like" changes so detections have something to fire on, using your operator profile:
```bash
# a: make a (new) bucket policy change on the backups bucket
# b: attach AdministratorAccess to dev-wildcard
aws iam attach-user-policy --user-name <prefix>-dev-wildcard \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile iamlab
# c: create an access key for another user
aws iam create-access-key --user-name <prefix>-dev-admin --profile iamlab
# d: remove then re-add the bucket public access block in the console
```
Wait ~15 minutes, then:
```bash
python3 scripts/export_cloudtrail.py --regions us-east-1 ap-south-1 --hours 6
python3 scripts/detect_cloudtrail.py evidence/cloudtrail/events.jsonl
```
Delete the access key from step (c) afterwards. To test the key-age check quickly:
`python3 scripts/audit_iam.py --max-key-age-days 0`.

### Optional: Splunk
Upload `evidence/cloudtrail/events.jsonl` (sourcetype `_json`, index `aws_lab`), then run the searches in
`detections/splunk_cloudtrail.spl`. Screenshot each result.

## 6. Document findings
Fill `report/REPORT_TEMPLATE.md`. For each finding record: what, where, severity, evidence (file/screenshot), risk,
fix, MITRE technique. `evidence/before/iam_findings.md` and `s3_findings.md` give you the table pre-built;
`docs/EXPECTED_FINDINGS.md` helps you check you found everything.

## 7. Remediate and re-scan
```bash
cd terraform/vulnerable && terraform destroy && cd ../remediated
terraform init && terraform apply && cd ../..
./scripts/run_assessment.sh after iamlab
python3 scripts/compare_runs.py
```
Any finding still present after remediation (for example the logging bucket's own access logging) should be written up as an
**accepted risk** with justification. Honest residual risk looks more professional than a perfect zero.

## 8. Clean up (stops any chance of a bill)
```bash
./scripts/cleanup.sh
```
Delete hand-made access keys, re-enable account-level Block Public Access, and check the billing page.

## 9. Publish
```bash
git init && git add . && git status    # check: no .tfstate, no keys, no account ID in evidence/prowler
git commit -m "AWS IAM & S3 security assessment"
```
Push to GitHub, pin the repo, put the link on your resume, and keep the README results table filled in.
