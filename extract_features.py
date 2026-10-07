import json
import csv
import os
import subprocess
import argparse
import hashlib
import time

SELECTED_FEATURES = ["svcscan.nservices", "svcscan.process_services"]
DEFAULT_HASH_LOG = "/home/okore/MemoryDumps/integrity.log"


def sha256_file(path, chunk_size=1 << 20):
    """Stream a file through SHA-256 without loading it into memory at once."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def log_hash(hash_log_path, artifact, path, digest):
    """Append a JSON-line integrity record. Never raises: a logging failure
    must not block the pipeline, but it is printed so it is not silent."""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "stage": "extract_features",
        "artifact": artifact,
        "path": path,
        "sha256": digest,
    }
    try:
        with open(hash_log_path, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        print(f"[-] Could not write integrity log entry: {e}")
    print(f"[+] SHA-256 ({artifact}): {digest}")


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
    parser.add_argument("--hash-log", default=DEFAULT_HASH_LOG,
                         help="Path to the append-only SHA-256 integrity log")
    args = parser.parse_args()

    # Hash the acquired image before it is touched by anything else. This is
    # the chain-of-custody anchor: every later artifact is derived from this
    # specific, fixed byte sequence, and the recorded digest lets an analyst
    # confirm the image was not altered between acquisition and analysis.
    print(f"[*] Hashing memory image {args.memory_path}...")
    image_hash = sha256_file(args.memory_path)
    log_hash(args.hash_log, "memory_image", args.memory_path, image_hash)

    svcscan_data = run_volatility_svcscan(args.memory_path)
    if not svcscan_data:
        print("[-] No services found or Volatility failed.")
        return

    features = extract_features(svcscan_data)

    # Write to a staging path in the same directory, then atomically rename
    # onto the watched output path. Wazuh FIM triggers the next stage on a
    # modification event at args.output; without this, FIM can fire while
    # the CSV is still being written, and the response script would read a
    # truncated file. os.replace() is atomic on POSIX filesystems when both
    # paths are on the same volume, so FIM only ever observes the complete
    # file.
    tmp_path = f"{args.output}.tmp"
    print(f"[*] Saving extracted features to {args.output}...")
    with open(tmp_path, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=SELECTED_FEATURES)
        writer.writeheader()
        writer.writerow(features)
    os.replace(tmp_path, args.output)

    csv_hash = sha256_file(args.output)
    log_hash(args.hash_log, "features_csv", args.output, csv_hash)

    print("[+] Feature extraction complete. Saved to", args.output)

if __name__ == "__main__":
    main()
