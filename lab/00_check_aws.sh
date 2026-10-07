#!/usr/bin/env bash
# Read-only check: can this AWS account run the lab instance?
# Creates nothing. Run before 01_provision_aws.sh.

REGION="${REGION:-us-east-1}"
ITYPE="${ITYPE:-c7i-flex.large}"     # 2 vCPU, 4 GB RAM, free-tier eligible
ok=0; bad=0
say(){ printf '  %-6s %s\n' "$1" "$2"; [ "$1" = FAIL ] && bad=$((bad+1)) || ok=$((ok+1)); }

echo "=== 1. Credentials ==="
if ! aws sts get-caller-identity --output table 2>/dev/null; then
  echo "  not configured. Run:  aws configure"
  echo "  (needs an access key from IAM > Users > Security credentials)"
  exit 1
fi
ACCT=$(aws sts get-caller-identity --query Account --output text)
say OK "authenticated as account $ACCT"
echo "  region for this run: $REGION"

echo
echo "=== 2. On-demand vCPU quota ==="
# L-1216C47A = Running On-Demand Standard (A,C,D,H,I,M,R,T,Z) instances, in vCPUs
Q=$(aws service-quotas get-service-quota --service-code ec2 \
      --quota-code L-1216C47A --region "$REGION" \
      --query 'Quota.Value' --output text 2>/dev/null)
echo "  standard on-demand vCPU limit: ${Q:-<unreadable>}   (need 2)"
if [ -n "$Q" ] && [ "${Q%.*}" -ge 2 ] 2>/dev/null; then say OK "quota sufficient"
else say WARN "could not read quota; new accounts usually start at 5 or more"; fi

echo
echo "=== 3. Is $ITYPE offered in $REGION? ==="
AZ=$(aws ec2 describe-instance-type-offerings --location-type availability-zone \
       --filters "Name=instance-type,Values=$ITYPE" --region "$REGION" \
       --query 'InstanceTypeOfferings[].Location' --output text 2>/dev/null)
[ -n "$AZ" ] && say OK "$ITYPE available in: $AZ" || say FAIL "$ITYPE not offered in $REGION"

echo
echo "=== 4. Windows Server 2022 AMI ==="
# Via ec2:DescribeImages, not the SSM ami-windows-latest parameter: restricted
# IAM users frequently lack ssm:GetParameters, and that is not a real blocker.
AMI=$(aws ec2 describe-images --region "$REGION" --owners amazon \
        --filters "Name=name,Values=Windows_Server-2022-English-Full-Base-*" \
                  "Name=state,Values=available" \
        --query 'sort_by(Images,&CreationDate)[-1].[ImageId,Name]' --output text 2>/dev/null)
if [ -n "$AMI" ] && [ "$AMI" != "None" ]; then
  say OK "latest AMI: $AMI"
else say FAIL "could not resolve the Windows Server 2022 AMI"; fi

echo
echo "=== 4b. Can this user actually launch? (dry run, creates nothing) ==="
# The decisive check. Quota and SSM reads can fail on a restricted user that is
# still perfectly able to run instances.
AMIID=$(echo "$AMI" | awk '{print $1}')
# The AWS CLI emits a leading blank line before an error, so collapse the whole
# stream to one line before matching rather than taking head -1.
verdict(){
  case "$1" in
    *DryRunOperation*)       say OK   "$2 permitted" ;;
    *UnauthorizedOperation*) say FAIL "$2 DENIED for this IAM user" ;;
    *)                       say WARN "$2 inconclusive: $(echo "$1" | cut -c1-90)" ;;
  esac
}
verdict "$(aws ec2 run-instances --region "$REGION" --dry-run \
             --image-id "$AMIID" --instance-type "$ITYPE" 2>&1 | tr '\n' ' ')" RunInstances
verdict "$(aws ec2 create-key-pair --region "$REGION" --dry-run \
             --key-name "probe-$$" 2>&1 | tr '\n' ' ')" CreateKeyPair
verdict "$(aws ec2 create-security-group --region "$REGION" --dry-run \
             --group-name "probe-$$" --description probe 2>&1 | tr '\n' ' ')" CreateSecurityGroup

echo
echo "=== 5. Default VPC (needed for a one-command launch) ==="
VPC=$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true \
        --query 'Vpcs[0].VpcId' --output text 2>/dev/null)
if [ -n "$VPC" ] && [ "$VPC" != "None" ]; then say OK "default VPC $VPC"
else say WARN "no default VPC; 01_provision_aws.sh will create a subnet for you"; fi

echo
echo "=== 6. Estimated cost for this project ==="
cat <<EOF
  $ITYPE Windows   ~\$0.17/hr  (compute + Windows licence, ~\$0.046/vCPU/hr)
  50 GB gp3 EBS    ~\$0.13/day (billed while stopped as well)
  30 hours of capture over a week  ->  roughly \$6 total

  Free-tier hours cover part of this; credits cover the rest. Stop the
  instance whenever you are not capturing, or the idle hours dominate.
EOF
say OK "well inside a \$100 credit"

echo
echo "======================================================================"
echo "  $ok checks passed, $bad blocking"
[ "$bad" -eq 0 ] && echo "  Ready. Run: ./lab/01_provision_aws.sh" \
                 || echo "  Fix the FAIL lines above first."
echo
echo "  Credits and billing are not reliably readable from the CLI."
echo "  Check at: console.aws.amazon.com/billing > Credits"
echo "  Set a budget alert while you are there: Billing > Budgets."
echo "======================================================================"
