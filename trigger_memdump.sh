#!/bin/bash

exec >> /var/log/wazuh_trigger.log 2>&1
echo "[$(date)] Starting trigger_memdump.sh"

input_json=$(cat)
agent_name=$(echo "$input_json" | jq -r '.parameters.alert.agent.name')
agent_ip=$(echo "$input_json" | jq -r '.parameters.alert.agent.ip')

AGENT_NAME="$agent_name"
AGENT_IP="$agent_ip"
SERVER_IP="10.0.2.15"
USERNAME="${WINRM_USER:-okore}"
: "${WINRM_PASS:?WINRM_PASS must be set in the environment}"
MEMDUMP_TOOL_PATH="C:\\Tools\\WinPMEM\\winpmem.exe"
# WinPMEM writes to a staging path first. Wazuh FIM watches the FINAL path
# below, not the staging path, so a second remote command performs an
# atomic rename on the endpoint only after WinPMEM has exited -- FIM never
# observes the image while it is still being written, closing the race
# where feature extraction could start reading a truncated/partial dump.
STAGING_DUMP_PATH="C:\\MemoryDumps\\memdump.raw.partial"
FINAL_DUMP_PATH="C:\\MemoryDumps\\memdump.raw"
SHARE_PATH="/home/okore/MemoryDumps"
HASH_LOG="$SHARE_PATH/integrity.log"

NETEXEC="sudo -u okore /home/okore/.local/bin/netexec"

# Stage 1: acquire memory to a non-watched path. This command blocks until
# winpmem.exe exits, so the rename in stage 2 only runs once acquisition is
# actually complete.
echo "Triggering memory dump on $AGENT_NAME ($AGENT_IP)..."
if ! $NETEXEC winrm "$AGENT_IP" --port 5985 -u "$USERNAME" -p "$WINRM_PASS" \
     -X "$MEMDUMP_TOOL_PATH $STAGING_DUMP_PATH"; then
  echo "[-] WinPMEM acquisition failed on $AGENT_NAME ($AGENT_IP); not publishing a partial image."
  exit 1
fi

# Stage 2: atomically publish the completed image at the path Wazuh FIM
# watches. move is atomic within the same NTFS volume.
echo "Acquisition complete; publishing to $FINAL_DUMP_PATH..."
if ! $NETEXEC winrm "$AGENT_IP" --port 5985 -u "$USERNAME" -p "$WINRM_PASS" \
     -X "cmd /c move /y $STAGING_DUMP_PATH $FINAL_DUMP_PATH"; then
  echo "[-] Failed to publish image to $FINAL_DUMP_PATH; FIM will not trigger extraction."
  exit 1
fi

# Hash the image as soon as it is visible to the manager over the SMB share.
# This is the chain-of-custody anchor for the acquisition stage; a second
# hash is computed independently by extract_features.py before analysis.
LOCAL_IMAGE="$SHARE_PATH/memdump.raw"
for _ in $(seq 1 30); do
  [ -s "$LOCAL_IMAGE" ] && break
  sleep 2
done
if [ -s "$LOCAL_IMAGE" ]; then
  DIGEST=$(sha256sum "$LOCAL_IMAGE" | awk '{print $1}')
  echo "[+] SHA-256 (memory_image, acquisition stage): $DIGEST"
  printf '{"ts":"%s","stage":"trigger_memdump","artifact":"memory_image","path":"%s","sha256":"%s"}\n' \
    "$(date -Iseconds)" "$LOCAL_IMAGE" "$DIGEST" >> "$HASH_LOG"
else
  echo "[-] Image not visible on share within timeout; skipping acquisition-stage hash."
fi

echo "Memory dump completed. Locate at $LOCAL_IMAGE"
exit 0
