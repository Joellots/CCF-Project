#!/usr/bin/env bash
# Provision the memory-forensics lab VM on Google Compute Engine.
set -euo pipefail

REGION="${REGION:-us-central1}"
ZONE="${ZONE:-${REGION}-a}"
MTYPE="${MTYPE:-e2-medium}"        # 2 vCPU, 4 GB RAM -> 4 GB memory dumps
NAME="${NAME:-malmem-winlab}"
DISK="${DISK:-50}"                 # GB. Windows base is ~32, leave room for a dump.

PROJ=$(gcloud config get-value project 2>/dev/null)
[ -n "$PROJ" ] && [ "$PROJ" != "(unset)" ] || { echo "[-] set a project: gcloud config set project <ID>"; exit 1; }
echo "[*] project $PROJ, zone $ZONE"

echo "[*] enabling Compute Engine API (no-op if already on)"
gcloud services enable compute.googleapis.com --project "$PROJ" -q

echo "[*] firewall: RDP restricted to your public IP"
MYIP=$(curl -fsS https://checkip.amazonaws.com | tr -d '\n')
if gcloud compute firewall-rules describe "$NAME-rdp" --project "$PROJ" >/dev/null 2>&1; then
  gcloud compute firewall-rules update "$NAME-rdp" --project "$PROJ" \
    --source-ranges "$MYIP/32" -q
  echo "    updated $NAME-rdp -> $MYIP/32"
else
  gcloud compute firewall-rules create "$NAME-rdp" --project "$PROJ" \
    --allow tcp:3389 --source-ranges "$MYIP/32" \
    --target-tags malmem-lab --description "RDP for memory forensics lab" -q
  echo "    created $NAME-rdp -> $MYIP/32"
fi

echo "[*] creating $NAME ($MTYPE, Windows Server 2022)"
gcloud compute instances create "$NAME" \
  --project "$PROJ" --zone "$ZONE" \
  --machine-type "$MTYPE" \
  --image-family windows-2022 --image-project windows-cloud \
  --boot-disk-size "${DISK}GB" --boot-disk-type pd-balanced \
  --tags malmem-lab \
  --metadata=enable-oslogin=FALSE \
  -q

IP=$(gcloud compute instances describe "$NAME" --project "$PROJ" --zone "$ZONE" \
      --format='value(networkInterfaces[0].accessConfigs[0].natIP)')

cat <<EOF

  Instance : $NAME  ($ZONE)
  RDP to   : $IP

  Windows needs about 3 minutes to finish first boot. Then set a password:

    gcloud compute reset-windows-password $NAME --zone $ZONE --user labadmin

  That prints the username and a generated password. Unlike AWS there is no
  key file to lose, and you can re-run it at any time to reset.

  Cost control:
    stop   : gcloud compute instances stop   $NAME --zone $ZONE
    start  : gcloud compute instances start  $NAME --zone $ZONE
    delete : gcloud compute instances delete $NAME --zone $ZONE -q

  Stop it whenever you are not capturing. A stopped instance bills only for
  the disk (~\$0.17/day). The external IP changes on restart, so re-run this
  script's firewall step, or just re-run the whole script, if your IP moves.
EOF
