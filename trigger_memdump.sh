#!/bin/bash

exec >> /var/log/wazuh_trigger.log 2>&1
echo "[$(date)] Starting trigger_memdump.sh"

input_json=$(cat)
agent_name=$(echo "$input_json" | jq -r '.parameters.alert.agent.name')
agent_ip=$(echo "$input_json" | jq -r '.parameters.alert.agent.ip')

AGENT_NAME="$agent_name"
AGENT_IP="$agent_ip"
SERVER_IP="10.0.2.15"
USERNAME="okore"
MEMDUMP_TOOL_PATH="C:\\Tools\\WinPMEM\\winpmem.exe"
DUMP_PATH="C:\\MemoryDumps\\memdump.raw"
SHARE_PATH="/home/okore/MemoryDumps"

# Trigger memory dump
echo "Triggering memory dump on $AGENT_NAME ($AGENT_IP)..."
sudo -u okore /home/okore/.local/bin/netexec winrm "$AGENT_IP" --port 5985 -u "$USERNAME" -p "auth_string" -X "$MEMDUMP_TOOL_PATH $DUMP_PATH"

echo "Memory dump completed. Locate at $SHARE_PATH"
exit 0
