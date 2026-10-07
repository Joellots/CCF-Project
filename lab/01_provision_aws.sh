#!/usr/bin/env bash
# Provision the memory-forensics lab instance on AWS EC2.
set -euo pipefail

REGION="${REGION:-us-east-1}"
# c7i-flex.large: 2 vCPU, 4 GB RAM -> 4 GB memory dumps.
# Chosen over t3.medium because new AWS accounts start on the Free Plan, which
# refuses any instance type that is not free-tier eligible. t3.medium is not;
# c7i-flex.large is, and gives the same vCPU/RAM on a newer core.
ITYPE="${ITYPE:-c7i-flex.large}"
NAME="${NAME:-malmem-winlab}"
KEY="${KEY:-$NAME-key}"
DISK="${DISK:-50}"                 # GB. Windows base is ~30, leave room for a dump.

echo "[*] resolving latest Windows Server 2022 AMI in $REGION"
# Resolved via ec2:DescribeImages rather than the /aws/service/ami-windows-latest
# SSM parameter, because ssm:GetParameters is not granted on many student and
# restricted IAM users. DescribeImages needs only EC2 read, which anyone able to
# launch an instance already has.
AMI=$(aws ec2 describe-images --region "$REGION" --owners amazon \
  --filters "Name=name,Values=Windows_Server-2022-English-Full-Base-*" \
            "Name=state,Values=available" \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)
[ -n "$AMI" ] && [ "$AMI" != "None" ] || { echo "[-] no Windows Server 2022 AMI found in $REGION"; exit 1; }
echo "    $AMI"

echo "[*] key pair"
if [ -f "$KEY.pem" ]; then
  echo "    reusing $KEY.pem"
else
  aws ec2 create-key-pair --region "$REGION" --key-name "$KEY" \
    --query KeyMaterial --output text > "$KEY.pem"
  chmod 400 "$KEY.pem"
  echo "    wrote $KEY.pem -- you cannot recover the Windows password without it"
fi

echo "[*] security group, RDP restricted to your public IP"
MYIP=$(curl -fsS https://checkip.amazonaws.com | tr -d '\n')
SG=$(aws ec2 create-security-group --region "$REGION" \
      --group-name "$NAME-sg" --description "malmem lab RDP" \
      --query GroupId --output text 2>/dev/null \
     || aws ec2 describe-security-groups --region "$REGION" \
          --filters "Name=group-name,Values=$NAME-sg" \
          --query 'SecurityGroups[0].GroupId' --output text)
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" \
  --protocol tcp --port 3389 --cidr "$MYIP/32" >/dev/null 2>&1 \
  || echo "    rule already present"
echo "    $SG allows 3389 from $MYIP only"

echo "[*] launching $ITYPE"
IID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI" --instance-type "$ITYPE" \
  --key-name "$KEY" --security-group-ids "$SG" \
  --block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":$DISK,\"VolumeType\":\"gp3\",\"DeleteOnTermination\":true}}]" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
  --query 'Instances[0].InstanceId' --output text)
echo "    $IID -- waiting for it to run"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$IID"

IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
      --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

cat <<EOF

  Instance : $IID
  RDP to   : $IP    user: Administrator

  Windows takes about 4 minutes before the password is available. Then:

    aws ec2 get-password-data --region $REGION --instance-id $IID \\
        --priv-launch-key $KEY.pem --query PasswordData --output text

  Cost control:
    stop      : aws ec2 stop-instances  --region $REGION --instance-ids $IID
    start     : aws ec2 start-instances --region $REGION --instance-ids $IID
    terminate : aws ec2 terminate-instances --region $REGION --instance-ids $IID

  Stop it whenever you are not capturing. Stopped instances bill only for the
  EBS volume (~\$0.13/day). The public IP changes on restart, so re-check it
  and update the security group rule if your own IP moves.
EOF
