#!/usr/bin/env bash
# Read-only check: can this GCP project run the lab VM?
# Creates nothing. Run before 01_provision_gcp.sh.

REGION="${REGION:-us-central1}"
ZONE="${ZONE:-${REGION}-a}"
MTYPE="${MTYPE:-e2-medium}"          # 2 vCPU, 4 GB RAM -> 4 GB memory dumps
ok=0; bad=0
say(){ printf '  %-6s %s\n' "$1" "$2"; [ "$1" = FAIL ] && bad=$((bad+1)) || ok=$((ok+1)); }

echo "=== 1. gcloud installed? ==="
if ! command -v gcloud >/dev/null 2>&1; then
  cat <<'EOF'
  FAIL   gcloud not installed. Install it with:

    curl -sSL https://sdk.cloud.google.com | bash
    exec -l $SHELL
    gcloud init

  Or on Ubuntu via apt:
    sudo apt install apt-transport-https ca-certificates gnupg curl
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg \
      | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] \
https://packages.cloud.google.com/apt cloud-sdk main" \
      | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list
    sudo apt update && sudo apt install google-cloud-cli
EOF
  exit 1
fi
say OK "gcloud $(gcloud version 2>/dev/null | head -1 | awk '{print $NF}')"

echo
echo "=== 2. Authenticated? ==="
ACCT=$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null)
if [ -z "$ACCT" ]; then
  echo "  FAIL   not logged in. Run:  gcloud auth login"; exit 1
fi
say OK "signed in as $ACCT"

echo
echo "=== 3. Project ==="
PROJ=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJ" ] || [ "$PROJ" = "(unset)" ]; then
  echo "  FAIL   no project set. List and pick one:"
  gcloud projects list 2>/dev/null | head -10
  echo "         gcloud config set project <PROJECT_ID>"
  exit 1
fi
say OK "project $PROJ"

echo
echo "=== 4. Billing enabled? (free trial credit still counts as billing) ==="
BILL=$(gcloud billing projects describe "$PROJ" \
        --format='value(billingEnabled)' 2>/dev/null)
case "$BILL" in
  True|true) say OK "billing linked" ;;
  False|false)
    say FAIL "billing NOT linked to $PROJ. Link it with:"
    echo "         gcloud billing accounts list"
    echo "         gcloud billing projects link $PROJ --billing-account=<ACCOUNT_ID>"
    ;;
  *) say WARN "could not read billing; check console.cloud.google.com/billing" ;;
esac

echo
echo "=== 5. Compute Engine API ==="
if gcloud services list --enabled --filter='config.name:compute.googleapis.com' \
     --format='value(config.name)' 2>/dev/null | grep -q compute; then
  say OK "compute.googleapis.com enabled"
else
  say WARN "not enabled yet. 01_provision_gcp.sh enables it (takes ~1 min)"
fi

echo
echo "=== 6. Can this account create instances? ==="
PERMS=$(gcloud projects test-iam-permissions "$PROJ" \
          --permissions=compute.instances.create,compute.firewalls.create,compute.disks.create \
          --format='value(permissions)' 2>/dev/null | tr '\n' ' ')
for p in compute.instances.create compute.firewalls.create compute.disks.create; do
  case "$PERMS" in *"$p"*) say OK "$p" ;; *) say FAIL "$p DENIED" ;; esac
done

echo
echo "=== 7. CPU quota in $REGION ==="
gcloud compute regions describe "$REGION" \
  --format='table(quotas.metric,quotas.limit,quotas.usage)' 2>/dev/null \
  | grep -Ei 'METRIC|^CPUS|IN_USE_ADDRESSES' | head -5 || \
  echo "  (could not read quota; trial projects normally allow 8-24 vCPUs)"

echo
echo "=== 8. Windows Server 2022 image ==="
IMG=$(gcloud compute images list --project windows-cloud \
        --filter='family~windows-2022 AND NOT name~core' \
        --format='value(name,family)' --limit=1 2>/dev/null)
if [ -n "$IMG" ]; then
  say OK "$IMG  (licence billed per vCPU-hour, no attestation needed)"
else
  say WARN "could not list windows-cloud images; the launch will still usually work"
fi

echo
echo "=== 9. Estimated cost ==="
cat <<EOF
  $MTYPE Windows   ~\$0.13/hr  (compute + Windows licence at ~\$0.046/vCPU/hr)
  50 GB pd-balanced ~\$0.17/day (billed while stopped as well)
  30 hours of capture over a week  ->  roughly \$5 total

  A new GCP account gets \$300 of trial credit valid for 90 days, so this
  costs nothing in practice. Stop the VM whenever you are not capturing.
EOF
say OK "well inside the trial credit"

echo
echo "======================================================================"
echo "  $ok checks passed, $bad blocking"
[ "$bad" -eq 0 ] && echo "  Ready. Run: ./lab/01_provision_gcp.sh" \
                 || echo "  Fix the FAIL lines above first."
echo "======================================================================"
