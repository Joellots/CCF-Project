#!/usr/bin/env bash
# Provision the memory-forensics lab VM on Azure for Students.
# Run from your Ubuntu box. Needs: az CLI (`sudo apt install azure-cli`).
set -euo pipefail

RG="${RG:-malmem-lab}"
LOC="${LOC:-eastus}"
VM="${VM:-winlab}"
SIZE="${SIZE:-Standard_B2s}"          # 2 vCPU, 4 GB RAM, 8 GB temp SSD
ADMIN="${ADMIN:-labadmin}"

# Windows Server, not Windows 10/11 client. Client images on Azure require
# attesting to Windows E3/E5 or VDA licensing, which Azure for Students does
# not include. Server 2022 deploys with its licence in the hourly price and
# runs WinPMEM, Volatility3 and Atomic Red Team identically.
IMAGE="MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition:latest"

echo "[*] checking vCPU quota in $LOC (student subscriptions are capped low)"
az vm list-usage -l "$LOC" -o table | grep -Ei 'Total Regional vCPUs|Standard Bs' || true

echo "[*] resource group"
az group create -n "$RG" -l "$LOC" -o none

read -rsp "Set admin password for $ADMIN (12+ chars, upper/lower/digit/symbol): " PW; echo

echo "[*] creating $VM ($SIZE) -- a few minutes"
az vm create \
  --resource-group "$RG" --name "$VM" \
  --image "$IMAGE" --size "$SIZE" \
  --admin-username "$ADMIN" --admin-password "$PW" \
  --os-disk-size-gb 128 --storage-sku StandardSSD_LRS \
  --public-ip-sku Standard --nsg-rule NONE -o none

echo "[*] locking RDP to your current public IP only"
MYIP=$(curl -fsS https://ifconfig.me)
az network nsg rule create -g "$RG" --nsg-name "${VM}NSG" -n allow-rdp-me \
  --priority 300 --access Allow --protocol Tcp --direction Inbound \
  --destination-port-ranges 3389 --source-address-prefixes "$MYIP/32" -o none
echo "    RDP open to $MYIP only. Re-run this line if your IP changes."

IP=$(az vm show -d -g "$RG" -n "$VM" --query publicIps -o tsv)
cat <<EOF

  RDP to: $IP    user: $ADMIN

  Cost control (important -- \$100 credit):
    stop  : az vm deallocate -g $RG -n $VM     # compute billing stops
    start : az vm start      -g $RG -n $VM
    wipe  : az group delete  -n $RG --yes      # removes everything

  Deallocate whenever you are not actively capturing. Compute is ~\$0.10/hr;
  the disk is ~\$0.30/day and continues while stopped.
EOF
