# Expected findings (answer key)

Use this to confirm your scans caught everything and to map each issue to a fix and an ATT&CK technique.
CIS references are to the *CIS AWS Foundations Benchmark*; check numbering against the benchmark version you use.

| # | Misconfiguration (Terraform resource) | Why it matters | Caught by | Fix (remediated stack) | MITRE |
|---|---|---|---|---|---|
| 1 | `aws_s3_bucket_public_access_block.public_data` all false | Removes the guardrail against public exposure | audit_s3, Prowler, Checkov, Access Analyzer | All four settings true on every bucket | T1530 |
| 2 | `aws_s3_bucket_policy.public_data` Principal `*` (Get + List) | Anyone can list and download objects | audit_s3 (CRITICAL), Prowler, Access Analyzer | No public policy; TLS-only deny policy | T1530 |
| 3 | `aws_s3_bucket.backups` no versioning / no logging | No recovery from overwrite or ransomware, no forensic trail | audit_s3, Checkov, Prowler | Versioning on, server access logs to a locked log bucket | T1485 / T1530 |
| 4 | `aws_iam_user.dev_admin` + AdministratorAccess | Single compromised credential = full account | audit_iam (CRITICAL), Prowler, Checkov | Group-based, scoped policies; admin only via MFA break-glass role | T1078.004 |
| 5 | `aws_iam_user_policy.dev_wildcard` `s3:*`, `ec2:*` on `*` | Over-broad service access | audit_iam (HIGH), Checkov | Specific actions on one bucket ARN | T1078.004 |
| 6 | Same policy: `iam:PassRole`, `AttachUserPolicy`, `CreatePolicyVersion`, `CreateAccessKey` on `*` | Privilege-escalation path to admin | audit_iam (HIGH), Checkov | Removed; add permission boundaries in real orgs | T1098 |
| 7 | Policies attached directly to users | Hard to audit; drift | Checkov | Policies attached to a group | n/a (hygiene) |
| 8 | `aws_iam_role.ec2_admin` + AdministratorAccess | Host compromise (SSRF/RCE) leads to full takeover via instance metadata | audit_iam, Prowler | App role scoped to read one bucket | T1078.004 |
| 9 | `aws_iam_role.open_trust` Principal `AWS:*`, no condition | Any AWS principal can attempt to assume the role | audit_iam (CRITICAL), Access Analyzer, Checkov | Trust only this account's root, with an MFA condition | T1078.004 |
| 10 | `aws_iam_account_password_policy.weak` | Weak passwords, no rotation | audit_iam, Prowler | 14+ chars, complexity, 90-day expiry, reuse prevention | T1110 |
| 11 | No MFA enforcement | Stolen password alone is enough | Prowler; audit_iam if a console profile exists | `require_mfa` deny-unless-MFA policy on the group | T1078.004 |
| 12 | Default encryption not explicitly configured | Compliance/auditability gap | audit_s3 (MEDIUM) | Explicit SSE-S3 default encryption | n/a |

## Accepted / residual risks to document in your report
* The access-log bucket does not log to another bucket (avoids infinite log chains); compensating control: restricted bucket policy, encryption, Block Public Access.
* SSE-S3 used instead of SSE-KMS to keep the lab at zero cost; production would use KMS with key policies.
* CloudTrail event history only keeps 90 days of management events; production needs an organisation trail to a protected bucket.
