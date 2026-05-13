#!/usr/bin/env python3
"""
CyberSentinel — Continuous log watcher
Watches a folder for new .csv / .json log files and auto-ingests them.

Usage:
  python watch_and_ingest.py --folder /path/to/logs --api http://localhost:8000

Works in Docker too — mount your SIEM log export folder as a volume.
"""
import argparse, time, os, json, requests
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--folder", default="./logs", help="Folder to watch")
parser.add_argument("--api",    default="http://localhost:8000", help="Backend API URL")
parser.add_argument("--interval", type=int, default=10, help="Poll interval seconds")
args = parser.parse_args()

FOLDER   = Path(args.folder)
API      = args.api.rstrip("/")
SEEN     = set()

FOLDER.mkdir(parents=True, exist_ok=True)
print(f"[CyberSentinel Watcher] Watching {FOLDER} every {args.interval}s → {API}")

def ingest_csv(path: Path):
    print(f"  → Ingesting CSV: {path.name}")
    with open(path, "rb") as f:
        r = requests.post(f"{API}/api/ingest/csv", files={"file": (path.name, f, "text/csv")}, timeout=60)
    print(f"  ✓ {r.json()}")

def ingest_json(path: Path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                log = json.loads(line)
                requests.post(f"{API}/api/ingest/log", json=log, timeout=5)
            except Exception as e:
                print(f"  ✗ {e}")
    print(f"  ✓ Done: {path.name}")

while True:
    for path in FOLDER.iterdir():
        if path in SEEN:
            continue
        if path.suffix == ".csv":
            try:
                ingest_csv(path)
                SEEN.add(path)
            except Exception as e:
                print(f"  ✗ {path.name}: {e}")
        elif path.suffix in (".json", ".ndjson", ".jsonl"):
            try:
                ingest_json(path)
                SEEN.add(path)
            except Exception as e:
                print(f"  ✗ {path.name}: {e}")
    time.sleep(args.interval)
