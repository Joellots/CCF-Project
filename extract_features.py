import json
import csv
import subprocess
import argparse

SELECTED_FEATURES = ["svcscan.nservices", "svcscan.process_services"]

def run_volatility_svcscan(memory_path, profile=None):
    """
    Run Volatility3 svcscan plugin and return parsed JSON.
    """
    print("[*] Running Volatility3 SvcScan plugin...")

    vol_cmd = [
        "sudo", "-u", "okore", "/home/okore/.local/bin/vol", "-f", memory_path,
        "-r", "json", 
        "windows.svcscan.SvcScan"
    ]

    if profile:
        vol_cmd.extend(["--profile", profile])

    try:
        result = subprocess.run(vol_cmd, capture_output=True, text=True, check=True)
        print("[+] Volatility scan completed successfully.")
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print("[-] Volatility error:", e.stderr)
        return []

def extract_features(svcscan_data):
    """
    Extract selected features from svcscan output.
    """
    print("[*] Extracting features...")
    
    process_pids = set()
    for svc in svcscan_data:
        pid = svc.get('PID', 0)
        if pid != 0:  
            process_pids.add(pid)
    
    features = {
        "svcscan.nservices": len(svcscan_data),
        "svcscan.process_services":  len(process_pids)
    }
    print(f"[+] Features extracted: {features}")
    return features

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("memory_path", help="Path to memory dump")
    parser.add_argument("--output", default="/home/okore/MemoryDumps/features.csv", help="Output CSV filename")
    args = parser.parse_args()

    svcscan_data = run_volatility_svcscan(args.memory_path)
    if not svcscan_data:
        print("[-] No services found or Volatility failed.")
        return

    features = extract_features(svcscan_data)

    print(f"[*] Saving extracted features to {args.output}...")
    with open(args.output, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=SELECTED_FEATURES)
        writer.writeheader()
        writer.writerow(features)

    print("[+] Feature extraction complete. Saved to", args.output)

if __name__ == "__main__":
    main()

