#!/usr/bin/env bash
# cleanup.sh - destroy BOTH stacks so nothing is left running or billable.
set -uo pipefail
for dir in terraform/vulnerable terraform/remediated; do
  if [ -d "$dir/.terraform" ]; then
    echo "Destroying $dir ..."
    (cd "$dir" && terraform destroy -auto-approve)
  fi
done
echo
echo "Manual checks:"
echo "  * IAM console: delete any access keys you created by hand"
echo "  * S3 console: confirm no iamlab-* buckets remain"
echo "  * If you disabled account-level Block Public Access for the lab, RE-ENABLE it"
echo "  * Billing console: confirm \$0.00 charges"
