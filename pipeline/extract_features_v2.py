#!/usr/bin/env python3
"""
Full memory-artefact feature extraction for the baseline-differential pipeline.

Replaces the 2-feature extractor. Emits a VolMemLyzer-comparable vector so that
(a) results are comparable to the published CIC-MalMem-2022 literature, and
(b) the baseline-differential transform has enough signal to work with.

Usage:
    extract_features_v2.py <memory.raw> --output features.csv [--label clean|infected]
                           [--host HOSTNAME] [--tag free-text]
"""
import argparse
import csv
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone

VOL = os.environ.get("VOL_BIN", "vol")

# plugin -> the rows it returns are aggregated by the handlers below
PLUGINS = {
    "pslist":     "windows.pslist.PsList",
    "dlllist":    "windows.dlllist.DllList",
    "handles":    "windows.handles.Handles",
    "ldrmodules": "windows.ldrmodules.LdrModules",
    "malfind":    "windows.malfind.Malfind",
    "modules":    "windows.modules.Modules",
    "svcscan":    "windows.svcscan.SvcScan",
    "callbacks":  "windows.callbacks.Callbacks",
}


def run_plugin(mem, plugin):
    """Run one Volatility3 plugin, return list-of-dicts (empty on failure)."""
    cmd = [VOL, "-q", "-f", mem, "-r", "json", plugin]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           check=True, timeout=1800)
        return json.loads(r.stdout) if r.stdout.strip() else []
    except subprocess.TimeoutExpired:
        print(f"[-] {plugin}: timed out", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"[-] {plugin}: {e.stderr.strip()[:200]}", file=sys.stderr)
    except json.JSONDecodeError:
        print(f"[-] {plugin}: unparseable JSON", file=sys.stderr)
    return []


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else 0.0


def feat_pslist(rows):
    pids = [r.get("PID") for r in rows if r.get("PID") is not None]
    return {
        "pslist.nproc":        len(rows),
        "pslist.nppid":        len({r.get("PPID") for r in rows}),
        "pslist.avg_threads":  _mean([r.get("Threads") for r in rows]),
        "pslist.avg_handlers": _mean([r.get("Handles") for r in rows]),
        "pslist.nprocs_wow64": sum(1 for r in rows if r.get("Wow64")),
        "pslist.ndistinct_pid": len(set(pids)),
    }


def feat_dlllist(rows):
    per_proc = Counter(r.get("PID") for r in rows)
    return {
        "dlllist.ndlls": len(rows),
        "dlllist.avg_dlls_per_proc": _mean(list(per_proc.values())),
        "dlllist.nproc_with_dlls": len(per_proc),
    }


def feat_handles(rows):
    types = Counter((r.get("Type") or "").lower() for r in rows)
    per_proc = Counter(r.get("PID") for r in rows)
    out = {
        "handles.nhandles": len(rows),
        "handles.avg_handles_per_proc": _mean(list(per_proc.values())),
    }
    for t in ("key", "file", "event", "desktop", "thread", "directory",
              "semaphore", "timer", "section", "mutant", "port"):
        out[f"handles.n{t}"] = types.get(t, 0)
    return out


def feat_ldrmodules(rows):
    n = len(rows) or 1
    nil = sum(1 for r in rows if r.get("InLoad") is False)
    nim = sum(1 for r in rows if r.get("InMem") is False)
    nii = sum(1 for r in rows if r.get("InInit") is False)
    return {
        "ldrmodules.not_in_load": nil,
        "ldrmodules.not_in_mem": nim,
        "ldrmodules.not_in_init": nii,
        "ldrmodules.not_in_load_avg": nil / n,
        "ldrmodules.not_in_mem_avg": nim / n,
        "ldrmodules.not_in_init_avg": nii / n,
    }


def feat_malfind(rows):
    per_proc = Counter(r.get("PID") for r in rows)
    prot = Counter((r.get("Protection") or "").upper() for r in rows)
    return {
        "malfind.ninjections": len(rows),
        "malfind.uniqueInjections": len(per_proc),
        "malfind.avg_per_proc": _mean(list(per_proc.values())),
        "malfind.commitCharge": sum(r.get("CommitCharge") or 0 for r in rows),
        "malfind.protection_rwx": prot.get("PAGE_EXECUTE_READWRITE", 0),
    }


def feat_modules(rows):
    return {"modules.nmodules": len(rows)}


def feat_svcscan(rows):
    pids = {r.get("PID") for r in rows if r.get("PID") not in (None, 0)}
    states = Counter((r.get("State") or "").upper() for r in rows)
    types = Counter((r.get("Type") or "").lower() for r in rows)
    return {
        "svcscan.nservices": len(rows),
        "svcscan.process_services": len(pids),
        "svcscan.nactive": states.get("SERVICE_RUNNING", 0),
        "svcscan.kernel_drivers": sum(v for k, v in types.items() if "kernel_driver" in k),
        "svcscan.fs_drivers": sum(v for k, v in types.items() if "file_system_driver" in k),
        "svcscan.shared_process_services": sum(v for k, v in types.items() if "share_process" in k),
        "svcscan.own_process_services": sum(v for k, v in types.items() if "own_process" in k),
    }


def feat_callbacks(rows):
    types = Counter((r.get("Type") or "") for r in rows)
    return {
        "callbacks.ncallbacks": len(rows),
        "callbacks.nanonymous": sum(1 for r in rows if not r.get("Module")),
        "callbacks.ngeneric": types.get("GenericKernelCallback", 0),
    }


HANDLERS = {
    "pslist": feat_pslist, "dlllist": feat_dlllist, "handles": feat_handles,
    "ldrmodules": feat_ldrmodules, "malfind": feat_malfind,
    "modules": feat_modules, "svcscan": feat_svcscan, "callbacks": feat_callbacks,
}


def extract(mem):
    feats = {}
    for short, plugin in PLUGINS.items():
        print(f"[*] {plugin} ...", file=sys.stderr)
        rows = run_plugin(mem, plugin)
        got = HANDLERS[short](rows)
        if not rows:
            # record the failure rather than silently emitting zeros
            got = {k: "" for k in got}
            print(f"[-] {short}: no rows -- features left EMPTY, not zero", file=sys.stderr)
        feats.update(got)
        print(f"[+] {short}: {len(rows)} rows", file=sys.stderr)
    return feats


def main():
    p = argparse.ArgumentParser()
    p.add_argument("memory_path")
    p.add_argument("--output", default="features.csv")
    p.add_argument("--label", choices=["clean", "infected", "unknown"], default="unknown",
                   help="ground truth, for dataset collection runs")
    p.add_argument("--host", default=os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "unknown")))
    p.add_argument("--tag", default="", help="sample name / scenario id")
    p.add_argument("--append", action="store_true")
    a = p.parse_args()

    if not os.path.exists(a.memory_path):
        sys.exit(f"[-] no such memory image: {a.memory_path}")

    feats = extract(a.memory_path)
    meta = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": a.host,
        "label": a.label,
        "tag": a.tag,
        "image": os.path.basename(a.memory_path),
        "image_bytes": os.path.getsize(a.memory_path),
    }
    row = {**meta, **feats}

    new = not (a.append and os.path.exists(a.output))
    with open(a.output, "a" if a.append else "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if new:
            w.writeheader()
        w.writerow(row)
    print(f"[+] {len(feats)} features -> {a.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
