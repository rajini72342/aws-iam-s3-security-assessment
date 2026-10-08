#!/usr/bin/env bash
# run_assessment.sh <before|after> [aws-profile]
# Runs Checkov (IaC), custom IAM/S3 audits, and Prowler (live) and stores
# everything under evidence/<label>/.
set -uo pipefail

LABEL="${1:?usage: run_assessment.sh <before|after> [aws-profile]}"
PROFILE="${2:-iamlab}"

case "$LABEL" in
  before) TF_DIR="terraform/vulnerable" ;;
  after)  TF_DIR="terraform/remediated" ;;
  *) echo "label must be 'before' or 'after'"; exit 1 ;;
esac

OUT="evidence/$LABEL"
mkdir -p "$OUT/checkov" "$OUT/prowler"
export AWS_PROFILE="$PROFILE"

echo "[1/4] Checkov (static IaC scan of $TF_DIR)..."
checkov -d "$TF_DIR" -o cli -o json --output-file-path "$OUT/checkov" || true

echo "[2/4] Custom IAM audit..."
python3 scripts/audit_iam.py --label "$LABEL" --out evidence

echo "[3/4] Custom S3 audit..."
python3 scripts/audit_s3.py --label "$LABEL" --out evidence --prefix "iamlab-"

echo "[4/4] Prowler (live account scan, IAM + S3 only)..."
if command -v prowler >/dev/null 2>&1; then
  prowler aws --profile "$PROFILE" --services iam s3 -M csv html \
    --output-directory "$OUT/prowler" || true
else
  echo "  prowler not installed - skipping (pipx install prowler)"
fi

echo
echo "Done. Evidence saved in $OUT/"
echo "Also capture (manually): IAM Access Analyzer findings screenshot + IAM credential report."
