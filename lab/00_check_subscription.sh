#!/usr/bin/env bash
# Read-only check: can this subscription run the lab VM?
# Creates nothing, changes nothing. Run before 01_provision_azure.sh.

LOC="${LOC:-eastus}"
SIZE="${SIZE:-Standard_B2s}"
ok=0; bad=0
say(){ printf '  %-6s %s\n' "$1" "$2"; [ "$1" = FAIL ] && bad=$((bad+1)) || ok=$((ok+1)); }

echo "=== 1. Logged in? ==="
if ! az account show >/dev/null 2>&1; then
  echo "  not logged in. Run:  az login"; exit 1
fi
az account list -o table

SUB=$(az account show --query id -o tsv)
NAME=$(az account show --query name -o tsv)
STATE=$(az account show --query state -o tsv)
echo
echo "=== 2. Active subscription ==="
echo "  name : $NAME"
echo "  id   : $SUB"
echo "  state: $STATE"
[ "$STATE" = "Enabled" ] && say OK "subscription enabled" || say FAIL "state is $STATE"

echo
echo "=== 3. Offer type ==="
QUOTA=$(az rest --method get \
  --url "https://management.azure.com/subscriptions/$SUB?api-version=2022-12-01" \
  --query "subscriptionPolicies.quotaId" -o tsv 2>/dev/null)
echo "  quotaId: ${QUOTA:-<unreadable>}"
case "$QUOTA" in
  *Student*)  say OK   "Azure for Students. \$100 credit, no credit card, expires 12 months from activation." ;;
  *Free*)     say OK   "Free Trial. \$200 credit for 30 days, then pay-as-you-go." ;;
  *MSDN*|*Enterprise*|*PayAsYouGo*) say OK "paid/benefit subscription, no student restrictions" ;;
  *)          say WARN "unrecognised offer; the checks below still apply" ;;
esac

echo
echo "=== 4. Resource providers ==="
for p in Microsoft.Compute Microsoft.Network Microsoft.Storage; do
  s=$(az provider show -n $p --query registrationState -o tsv 2>/dev/null)
  [ "$s" = "Registered" ] && say OK "$p registered" \
    || say WARN "$p is '$s' (az provider register -n $p)"
done

echo
echo "=== 5. vCPU quota in $LOC ==="
az vm list-usage -l "$LOC" -o table 2>/dev/null | grep -Ei 'Name|Total Regional vCPUs|Standard BS Family' || true
REG=$(az vm list-usage -l "$LOC" --query "[?contains(name.value,'cores')]|[0].limit" -o tsv 2>/dev/null)
BS=$(az vm list-usage -l "$LOC" --query "[?contains(name.value,'standardBSFamily')]|[0].limit" -o tsv 2>/dev/null)
echo "  regional vCPU limit: ${REG:-?}   B-series limit: ${BS:-?}   (need 2)"
if [ -n "$BS" ] && [ "$BS" -ge 2 ] 2>/dev/null; then say OK "B-series quota sufficient for $SIZE"
elif [ -n "$REG" ] && [ "$REG" -ge 2 ] 2>/dev/null; then say WARN "no explicit B-series quota; regional quota looks sufficient"
else say FAIL "quota too low in $LOC. Try LOC=westus2 or northeurope"; fi

echo
echo "=== 6. Is $SIZE offered in $LOC? ==="
R=$(az vm list-skus -l "$LOC" --size "$SIZE" --query "[0].restrictions" -o tsv 2>/dev/null)
if az vm list-skus -l "$LOC" --size "$SIZE" -o tsv 2>/dev/null | grep -q .; then
  [ -z "$R" ] && say OK "$SIZE available, no restrictions" || say FAIL "$SIZE restricted here: $R"
else say FAIL "$SIZE not offered in $LOC"; fi

echo
echo "=== 7. Windows Server 2022 image ==="
if az vm image list --publisher MicrosoftWindowsServer --offer WindowsServer \
     --sku 2022-datacenter-azure-edition --all -o tsv 2>/dev/null | head -1 | grep -q .; then
  say OK "Windows Server 2022 image reachable (licence included in hourly price)"
else say WARN "could not list the image; the deployment will still usually work"; fi

echo
echo "=== 8. Windows 11 client (expected to be unavailable) ==="
if az vm image list --publisher MicrosoftWindowsDesktop --offer Windows-11 --all -o tsv 2>/dev/null | head -1 | grep -q .; then
  echo "  image is listed, but deploying it still requires attesting to E3/E5 or VDA"
  say WARN "listed; Server 2022 remains the safe choice on a student subscription"
else say OK "not available, as expected. Server 2022 is the right image."; fi

echo
echo "======================================================================"
echo "  $ok checks passed, $bad blocking"
[ "$bad" -eq 0 ] && echo "  Ready. Run: ./lab/01_provision_azure.sh" \
                 || echo "  Fix the FAIL lines above first."
echo
echo "  Credit balance is NOT available from the CLI for student offers."
echo "  Check it at: portal.azure.com > Cost Management + Billing > Credits"
echo "======================================================================"
