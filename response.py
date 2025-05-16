import subprocess
import json
import sys
import requests

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"
ADMIN_USER = "okore"
ADMIN_PASS = "auth_string"

def run_prediction(features_csv):
    result = subprocess.run(["sudo", "-u", "okore", "/usr/bin/python3", "/home/okore/ccf-scripts/predict.py", features_csv], capture_output=True, text=True)
    print(json.dumps(eval(result.stdout.strip())))
    try:
        return json.dumps(eval(result.stdout.strip()))
    except json.JSONDecodeError:
        print("[-] Prediction failed or invalid output.")
        return None

def isolate_windows_agent(agent_ip):
    print(f"[*] Isolating Windows agent at {agent_ip}...")

    cmd = 'Get-NetAdapter | Disable-NetAdapter -Confirm:$false'

    try:
        subprocess.run([
            "sudo", "-u", "okore", "/home/okore/.local/bin/netexec", "winrm", agent_ip, "--port", "5985",
            "-u", ADMIN_USER, "-p", ADMIN_PASS,
            "-X", cmd])
        print("[+] Windows agent isolated.")
    except subprocess.CalledProcessError as e:
        print("[-] Failed to isolate agent:", e)

def alert_team(proba, agent_ip):
    print("[*] Alerting security team via Slack...")
    msg = {
        "text": f"🚨 *Malware Detected*\n\n*Prediction:* Malicious\n*Confidence:* {proba}\n*Agent:* {agent_ip}"
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

    result = eval(run_prediction(features_csv))
    
    if not result:
        return

    prediction = result.get("prediction")
    pred_class = result.get("class")
    proba = result.get("malicious_probability")

    print(f"[+] Prediction: {prediction}, Class: {pred_class}, Malicious Probability: {proba}")

    if prediction == 1:
        print("[!] Malicious activity detected! Executing response...")
        isolate_windows_agent(agent_ip)
        alert_team(proba, agent_ip)
    else:
        print("[+] No malicious activity. No response needed.")

if __name__ == "__main__":
    main()

