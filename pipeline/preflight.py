#!/usr/bin/env python3
"""
Preflight check. Run this on ONE memory dump before starting collection.

Verifies that every Volatility3 plugin runs on this host's images and that the
column names extract_features_v2.py depends on are actually present. A silent
name mismatch yields empty features, which is only discoverable after the fact.

    python3 pipeline/preflight.py /path/to/one_dump.raw
"""
import json
import subprocess
import sys
import time

VOL = "vol"

# plugin -> fields extract_features_v2.py reads from it
NEEDS = {
    "windows.pslist.PsList":        ["PID", "PPID", "Threads", "Handles", "Wow64"],
    "windows.dlllist.DllList":      ["PID"],
    "windows.handles.Handles":      ["PID", "Type"],
    "windows.ldrmodules.LdrModules": ["InLoad", "InMem", "InInit"],
    "windows.malfind.Malfind":      ["PID", "Protection", "CommitCharge"],
    "windows.modules.Modules":      [],
    "windows.svcscan.SvcScan":      ["PID", "State", "Type"],
    "windows.callbacks.Callbacks":  ["Type", "Module"],
}

def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    mem = sys.argv[1]
    ok, warn, fail = [], [], []

    for plugin, needed in NEEDS.items():
        t0 = time.time()
        print(f"[*] {plugin} ...", flush=True)
        try:
            r = subprocess.run([VOL, "-q", "-f", mem, "-r", "json", plugin],
                               capture_output=True, text=True, timeout=3600)
        except subprocess.TimeoutExpired:
            fail.append((plugin, "timed out after 60 min")); continue
        dt = time.time() - t0
        if r.returncode != 0:
            fail.append((plugin, r.stderr.strip().splitlines()[-1][:120] if r.stderr else "nonzero exit"))
            continue
        try:
            rows = json.loads(r.stdout) if r.stdout.strip() else []
        except json.JSONDecodeError:
            fail.append((plugin, "output is not JSON")); continue
        if not rows:
            warn.append((plugin, f"ran in {dt:.0f}s but returned 0 rows")); continue

        present = set(rows[0].keys())
        missing = [f for f in needed if f not in present]
        if missing:
            warn.append((plugin, f"{len(rows)} rows in {dt:.0f}s; MISSING {missing}; "
                                 f"actual columns = {sorted(present)}"))
        else:
            ok.append((plugin, f"{len(rows)} rows in {dt:.0f}s"))

    print("\n" + "=" * 70)
    for p, m in ok:   print(f"  OK    {p:34s} {m}")
    for p, m in warn: print(f"  WARN  {p:34s} {m}")
    for p, m in fail: print(f"  FAIL  {p:34s} {m}")
    print("=" * 70)
    if fail or warn:
        print("\nFix these before collecting. A WARN about missing columns means")
        print("extract_features_v2.py needs its field names changed to the actual")
        print("column names printed above. Send me that output and I will patch it.")
        sys.exit(1)
    print("\nAll plugins clean. Total runtime above is PER DUMP: multiply by 24")
    print("(12 trials x 2 dumps) to budget the collection run.")

if __name__ == "__main__":
    main()
