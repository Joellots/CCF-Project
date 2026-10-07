#!/usr/bin/env bash
# Paired (within-subject) memory-capture protocol.
#
# WHY PAIRED:  CIC-MalMem-2022 compares benign captures from one machine state
# against malware captures from another, so class and capture protocol are
# collinear (99.08% of that corpus is perfectly separated on protocol alone).
# Here every infected capture has a CLEAN capture from the same VM, same
# snapshot, same workload, minutes earlier. The host state is held fixed by
# construction, so a pre/post difference can only come from the detonation.
#
# Run on the Wazuh manager. Requires: VBoxManage, netexec, the v2 extractor.
set -euo pipefail

VM="${VM:-Win10-Agent}"
SNAP="${SNAP:-clean-baseline}"
AGENT_IP="${AGENT_IP:?set AGENT_IP}"
: "${WINRM_USER:?}" "${WINRM_PASS:?}"
SHARE="${SHARE:-/home/okore/MemoryDumps}"
OUT="${OUT:-$SHARE/paired_dataset.csv}"
SAMPLES_DIR="${SAMPLES_DIR:-/home/okore/samples}"
SETTLE="${SETTLE:-120}"        # seconds to let the desktop settle before PRE
DETONATE="${DETONATE:-180}"    # seconds malware runs before POST capture
EXTRACT="${EXTRACT:-$PWD/pipeline/extract_features_v2.py}"

# Workload profiles give the CLEAN baseline realistic variance. Without this the
# baseline has near-zero dispersion and every deviation looks anomalous --
# exactly the degenerate case seen in the public corpus (benign varies over only
# 3 distinct values of svcscan.kernel_drivers across 29,298 samples).
PROFILES=("idle" "browser" "office" "browser+office" "compile")

winrm() { netexec winrm "$AGENT_IP" --port 5985 -u "$WINRM_USER" -p "$WINRM_PASS" -X "$1"; }

apply_workload() {
  case "$1" in
    idle)           : ;;
    browser)        winrm 'Start-Process msedge "https://example.org","https://wikipedia.org"' ;;
    office)         winrm 'Start-Process notepad; Start-Process mspaint' ;;
    browser+office) winrm 'Start-Process msedge "https://example.org"; Start-Process notepad' ;;
    compile)        winrm 'Get-ChildItem C:\Windows\System32 -Recurse -EA SilentlyContinue | Out-Null' ;;
  esac
}

capture() {  # capture <label> <tag> <trial>
  local label="$1" tag="$2" trial="$3"
  local img="C:\\MemoryDumps\\${label}_${trial}.raw"
  echo "  [*] capturing $label (trial $trial, $tag)"
  winrm "C:\\Tools\\WinPMEM\\winpmem.exe $img" >/dev/null
  local local_img="$SHARE/${label}_${trial}.raw"
  for _ in $(seq 60); do [ -s "$local_img" ] && break; sleep 5; done
  python3 "$EXTRACT" "$local_img" --output "$OUT" --append \
          --label "$label" --host "$VM" --tag "${tag}|trial=${trial}"
  rm -f "$local_img"        # dumps are GB-scale; keep features, not images
}

N="${N:-12}"
mapfile -t SAMPLES < <(ls "$SAMPLES_DIR" 2>/dev/null || true)
echo "[*] $N trials | ${#SAMPLES[@]} samples | out=$OUT"

for i in $(seq 1 "$N"); do
  profile="${PROFILES[$(( (i-1) % ${#PROFILES[@]} ))]}"
  echo "[=] trial $i/$N  workload=$profile"

  VBoxManage snapshot "$VM" restore "$SNAP" >/dev/null
  VBoxManage startvm "$VM" --type headless >/dev/null
  sleep "$SETTLE"
  apply_workload "$profile"
  sleep 45

  capture clean "workload=$profile" "$i"          # ---- PRE (paired control)

  if [ "${#SAMPLES[@]}" -gt 0 ]; then
    s="${SAMPLES[$(( (i-1) % ${#SAMPLES[@]} ))]}"
    echo "  [!] detonating $s"
    winrm "Copy-Item \\\\$HOSTNAME\\samples\\$s C:\\Users\\Public\\$s; Start-Process C:\\Users\\Public\\$s"
    sleep "$DETONATE"
    capture infected "workload=$profile|sample=$s" "$i"   # ---- POST (same host state)
  fi

  VBoxManage controlvm "$VM" poweroff >/dev/null || true
  VBoxManage snapshot "$VM" restore "$SNAP" >/dev/null
done

echo "[+] done -> $OUT"
echo "    fit    : python3 pipeline/baseline_diff.py fit   $OUT --out baseline.json"
echo "    score  : python3 pipeline/baseline_diff.py score $OUT --model baseline.json"
