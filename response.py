import hashlib
import json
import os
import subprocess
import sys
import time

import requests

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
ADMIN_USER = os.environ.get("WINRM_USER", "okore")
ADMIN_PASS = os.environ["WINRM_PASS"]
HASH_LOG = os.environ.get("HASH_LOG", "/home/okore/MemoryDumps/integrity.log")


def log_hash(artifact, digest, extra=None):
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "stage": "response",
        "artifact": artifact,
        "sha256": digest,
    }
    if extra:
        record.update(extra)
    try:
        with open(HASH_LOG, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        print(f"[-] Could not write integrity log entry: {e}")


def run_prediction(features_csv):
    result = subprocess.run(["sudo", "-u", "okore", "/usr/bin/python3",
                             "/home/okore/ccf-scripts/predict.py", features_csv],
                            capture_output=True, text=True)
    try:
        decision = json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        print(f"[-] Prediction failed or invalid output: {result.stdout[:200]!r}")
        return None
    decision_hash = hashlib.sha256(
        json.dumps(decision, sort_keys=True).encode()
    ).hexdigest()
    log_hash("classification_decision_received", decision_hash)
    return decision


def isolate_windows_agent(agent_ip):
    """Request network isolation and report success only if the remote
    command actually returned success -- the previous version printed
    "isolated" unconditionally regardless of the command's exit status."""
    print(f"[*] Isolating Windows agent at {agent_ip}...")

    cmd = 'Get-NetAdapter | Disable-NetAdapter -Confirm:$false'

    result = subprocess.run([
        "sudo", "-u", "okore", "/home/okore/.local/bin/netexec", "winrm", agent_ip, "--port", "5985",
        "-u", ADMIN_USER, "-p", ADMIN_PASS,
        "-X", cmd], capture_output=True, text=True)

    log_hash("isolation_command_output",
             hashlib.sha256(result.stdout.encode()).hexdigest(),
             extra={"agent_ip": agent_ip, "returncode": result.returncode})

    if result.returncode != 0:
        print(f"[-] Isolation command failed (exit {result.returncode}): "
              f"{result.stderr.strip()[:300]}")
        return False

    print("[+] Isolation command returned success.")
    print("[!] This confirms the remote command exited cleanly, not that the "
          "network adapters are actually down -- an independent connectivity "
          "check (e.g. a reachability probe against the endpoint) is still "
          "needed to verify containment.")
    return True


def alert_team(proba, agent_ip, isolated):
    print("[*] Alerting security team via Slack...")
    status = "isolation command succeeded" if isolated else "ISOLATION FAILED -- manual action needed"
    msg = {
        "text": f"🚨 *Malware Detected*\n\n*Prediction:* Malicious\n*Confidence:* {proba}\n"
                f"*Agent:* {agent_ip}\n*Containment:* {status}"
    }
    try:
        r = requests.post(SLACK_WEBHOOK_URL, json=msg)
        if r.status_code == 200:
            print("[+] Alert sent to Slack.")
        else:
            print(f"[-] Slack error: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[-] Failed to send alert: {e}")


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 response.py features.csv <agent_ip>")
        sys.exit(1)

    features_csv = sys.argv[1]
    agent_ip = sys.argv[2]

    result = run_prediction(features_csv)

    if not result:
        return

    prediction = result.get("prediction")
    pred_class = result.get("class")
    proba = result.get("malicious_probability")

    print(f"[+] Prediction: {prediction}, Class: {pred_class}, Malicious Probability: {proba}")

    if prediction == 1:
        print("[!] Malicious activity detected! Executing response...")
        isolated = isolate_windows_agent(agent_ip)
        alert_team(proba, agent_ip, isolated)
    else:
        print("[+] No malicious activity. No response needed.")


if __name__ == "__main__":
    main()
