#!/usr/bin/env python3
"""
CyberSentinel — Wazuh alerts.json Streamer

Tails Wazuh's alerts.json locally with byte-offset tracking.
Deployed ON the Wazuh server inside Docker — reads alerts.json as read-only mount.
NOTHING gets modified, deleted, or written to the Wazuh directories.

Smart filtering to handle high-volume logs (1000s/min):
  - Level 0-3:  DROP (noise — syslog, file integrity checks, etc.)
  - Level 4-6:  SAMPLE 1 in N (moderate — auth info, policy changes)
  - Level 7+:   KEEP ALL (important — attacks, brute force, exploits)

First run:  reads ALL existing alerts (full history)
After that: reads ONLY new alerts since last position
"""
import json
import os
import random
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── config ────────────────────────────────────────────────────────────────────

ALERTS_PATH = Path(os.getenv("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json"))
API_BASE = os.getenv("WAZUH_API_URL", "http://backend:8000").rstrip("/")
OFFSET_FILE = Path(os.getenv("WAZUH_OFFSET_FILE", "/app/data/wazuh_offset.json"))
INTERVAL = int(os.getenv("WAZUH_POLL_INTERVAL", "5"))
BATCH_SIZE = int(os.getenv("WAZUH_BATCH_SIZE", "200"))
TRAIN_THRESHOLD = int(os.getenv("WAZUH_TRAIN_THRESHOLD", "500"))
ARCHIVE_THRESHOLD = int(os.getenv("WAZUH_ARCHIVE_THRESHOLD", "5000"))

# Smart filtering
MIN_LEVEL = int(os.getenv("WAZUH_MIN_LEVEL", "4"))
SAMPLE_BELOW = int(os.getenv("WAZUH_SAMPLE_BELOW", "7"))
SAMPLE_RATE = int(os.getenv("WAZUH_SAMPLE_RATE", "10"))
MAX_PER_MINUTE = int(os.getenv("WAZUH_MAX_PER_MINUTE", "500"))

# ── filter stats ─────────────────────────────────────────────────────────────
filter_stats = defaultdict(int)
minute_counter = {"count": 0, "minute": 0}


def get_rule_level(raw_alert: dict) -> int:
    """Extract the Wazuh rule level from a raw alert."""
    rule = raw_alert.get("rule", {})
    if isinstance(rule, dict):
        level = rule.get("level", 0)
    else:
        level = 0
    try:
        return int(level)
    except (ValueError, TypeError):
        return 0


def should_ingest(raw_alert: dict) -> str:
    """
    Decide whether to ingest this alert.
    Returns: 'keep', 'sample', or 'drop'

    Wazuh levels:
      0-3:  Noise (syslog, file checks, system msgs)    → DROP
      4-6:  Moderate (auth info, policy, errors)         → SAMPLE 1/N
      7-9:  Important (bad auth, scans, attacks)         → KEEP ALL
      10-12: High (exploit, brute force, rootkit)        → KEEP ALL
      13-15: Critical (active attack, breach)            → KEEP ALL
    """
    level = get_rule_level(raw_alert)

    if level < MIN_LEVEL:
        return "drop"

    if level < SAMPLE_BELOW:
        if random.randint(1, SAMPLE_RATE) == 1:
            return "sample"
        return "drop"

    return "keep"


def check_rate_limit() -> bool:
    """Check if we're within the per-minute rate limit."""
    if MAX_PER_MINUTE <= 0:
        return True
    current_minute = int(time.time() / 60)
    if minute_counter["minute"] != current_minute:
        minute_counter["minute"] = current_minute
        minute_counter["count"] = 0
    if minute_counter["count"] >= MAX_PER_MINUTE:
        return False
    minute_counter["count"] += 1
    return True


# ── offset tracking ──────────────────────────────────────────────────────────

def load_offset() -> dict:
    if OFFSET_FILE.exists():
        try:
            with open(OFFSET_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"byte_offset": 0, "lines_read": 0, "last_run": None, "total_ingested": 0}


def save_offset(state: dict):
    OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    with open(OFFSET_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ── wazuh field mapping ─────────────────────────────────────────────────────

def flatten_wazuh(alert: dict, prefix: str = "") -> dict:
    """Flatten nested Wazuh JSON into dot-notation keys."""
    flat = {}
    for key, value in alert.items():
        full_key = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
        if isinstance(value, dict):
            flat.update(flatten_wazuh(value, full_key))
        elif isinstance(value, list):
            flat[full_key] = ", ".join(str(v) for v in value) if value else ""
        else:
            flat[full_key] = value
    return flat


def map_wazuh_alert(raw_alert: dict) -> dict:
    flat = flatten_wazuh(raw_alert)
    if "@timestamp" not in flat and "timestamp" in flat:
        flat["@timestamp"] = flat["timestamp"]
    return flat


# ── API calls ────────────────────────────────────────────────────────────────

def send_batch(alerts: list) -> bool:
    try:
        resp = requests.post(
            f"{API_BASE}/api/ingest/bulk", json=alerts, timeout=60,
            headers={"Content-Type": "application/json"},
        )
        return resp.status_code == 200
    except requests.ConnectionError:
        print(f"  ✗ Cannot connect to {API_BASE}")
        return False
    except Exception as e:
        print(f"  ✗ Batch error: {e}")
        return False


def trigger_ml_train():
    try:
        resp = requests.post(f"{API_BASE}/api/ml/train", timeout=120)
        data = resp.json()
        print(f"  🧠 ML train: {data.get('status')} — {data.get('ip_count', '?')} IPs, "
              f"{data.get('anomalies', '?')} anomalies")
    except Exception as e:
        print(f"  ⚠ ML train failed: {e}")


def trigger_archive():
    try:
        resp = requests.post(f"{API_BASE}/api/archive/run", timeout=120)
        data = resp.json()
        print(f"  📦 Archive: {data.get('archived', '?')} events archived")
    except Exception as e:
        print(f"  ⚠ Archive failed: {e}")


def trigger_baseline_build():
    try:
        resp = requests.post(f"{API_BASE}/api/baseline/build-all", timeout=120)
        data = resp.json()
        print(f"  📊 Baselines: {data.get('baselines_built', '?')} built")
    except Exception as e:
        print(f"  ⚠ Baseline build failed: {e}")


def wait_for_backend(max_wait: int = 120):
    print(f"[Watcher] Waiting for backend at {API_BASE} ...")
    start = time.time()
    while time.time() - start < max_wait:
        try:
            resp = requests.get(f"{API_BASE}/api/health", timeout=5)
            if resp.status_code == 200:
                print(f"[Watcher] Backend ready ✓")
                return
        except Exception:
            pass
        time.sleep(3)
    print(f"[Watcher] Backend not reachable after {max_wait}s — starting anyway")


# ── main loop ────────────────────────────────────────────────────────────────

def tail_alerts():
    state = load_offset()
    is_first_run = state["byte_offset"] == 0

    if is_first_run:
        print(f"[Watcher] FIRST RUN — will ingest entire alerts.json history")
    else:
        print(f"[Watcher] Resuming from offset {state['byte_offset']:,} "
              f"({state['lines_read']:,} lines read before)")

    # Wait for file to exist
    if not ALERTS_PATH.exists():
        print(f"[Watcher] Waiting for {ALERTS_PATH} ...")
        while not ALERTS_PATH.exists():
            time.sleep(INTERVAL)
        print(f"[Watcher] File found ✓")

    session_ingested = 0
    since_last_train = 0
    since_last_archive = 0

    while True:
        try:
            file_size = ALERTS_PATH.stat().st_size
        except Exception:
            time.sleep(INTERVAL)
            continue

        # File rotation detection (Wazuh rotates daily)
        if file_size < state["byte_offset"]:
            print(f"[Watcher] File rotated — resetting offset")
            state["byte_offset"] = 0

        if file_size == state["byte_offset"]:
            time.sleep(INTERVAL)
            continue

        # Read new lines
        new_alerts_batch = []
        new_offset = state["byte_offset"]
        cycle_total = 0
        cycle_kept = 0
        cycle_dropped = 0

        try:
            with open(ALERTS_PATH, "r", encoding="utf-8", errors="replace") as f:
                f.seek(state["byte_offset"])

                while True:
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        break  # incomplete line, wait for next cycle

                    new_offset = f.tell()
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        raw_alert = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    cycle_total += 1

                    # ── Smart filtering ──
                    decision = should_ingest(raw_alert)
                    if decision == "drop":
                        cycle_dropped += 1
                        filter_stats["dropped"] += 1
                        continue

                    if not check_rate_limit():
                        filter_stats["rate_limited"] += 1
                        continue

                    if decision == "sample":
                        filter_stats["sampled"] += 1
                    else:
                        filter_stats["kept"] += 1

                    mapped = map_wazuh_alert(raw_alert)
                    new_alerts_batch.append(mapped)
                    cycle_kept += 1

                    # Send in batches
                    if len(new_alerts_batch) >= BATCH_SIZE:
                        if send_batch(new_alerts_batch):
                            state["byte_offset"] = new_offset
                            state["lines_read"] += len(new_alerts_batch)
                            state["total_ingested"] += len(new_alerts_batch)
                            session_ingested += len(new_alerts_batch)
                            since_last_train += len(new_alerts_batch)
                            since_last_archive += len(new_alerts_batch)
                            save_offset(state)
                            ts = datetime.now().strftime("%H:%M:%S")
                            print(f"  [{ts}] Sent {len(new_alerts_batch)} "
                                  f"(total: {state['total_ingested']:,})")
                        new_alerts_batch = []

        except Exception as e:
            print(f"  ✗ Read error: {e}")
            time.sleep(INTERVAL)
            continue

        # Log filter stats
        if cycle_total > 0:
            pct = round(cycle_dropped / cycle_total * 100)
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"  [{ts}] Filter: {cycle_total} read → {cycle_kept} kept, "
                  f"{cycle_dropped} dropped ({pct}% noise)")

        # Send remaining
        if new_alerts_batch:
            if send_batch(new_alerts_batch):
                state["byte_offset"] = new_offset
                state["lines_read"] += len(new_alerts_batch)
                state["total_ingested"] += len(new_alerts_batch)
                session_ingested += len(new_alerts_batch)
                since_last_train += len(new_alerts_batch)
                since_last_archive += len(new_alerts_batch)
                save_offset(state)

        # Auto-triggers
        if since_last_train >= TRAIN_THRESHOLD:
            print(f"[Watcher] Triggering ML train ({since_last_train:,} new)...")
            trigger_baseline_build()
            trigger_ml_train()
            since_last_train = 0

        if since_last_archive >= ARCHIVE_THRESHOLD:
            print(f"[Watcher] Triggering archive ({since_last_archive:,} new)...")
            trigger_archive()
            since_last_archive = 0

        # First run complete
        if is_first_run and session_ingested > 0 and new_offset >= file_size:
            print(f"\n[Watcher] ═══ FIRST RUN COMPLETE ═══")
            print(f"[Watcher] Ingested {session_ingested:,} historical alerts")
            trigger_baseline_build()
            trigger_ml_train()
            trigger_archive()
            is_first_run = False
            since_last_train = 0
            since_last_archive = 0
            print(f"[Watcher] Now watching for new alerts every {INTERVAL}s\n")

        time.sleep(INTERVAL)


if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   CyberSentinel — Wazuh alerts.json Streamer           ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  File       : {ALERTS_PATH}")
    print(f"  Backend    : {API_BASE}")
    print(f"  Interval   : {INTERVAL}s | Batch: {BATCH_SIZE}")
    print(f"  ── Smart Filter ──")
    print(f"  Drop       : level <{MIN_LEVEL} (noise)")
    print(f"  Sample     : level {MIN_LEVEL}-{SAMPLE_BELOW-1} (1 in {SAMPLE_RATE})")
    print(f"  Keep all   : level {SAMPLE_BELOW}+")
    print(f"  Rate limit : {MAX_PER_MINUTE}/min" if MAX_PER_MINUTE > 0 else "  Rate limit : unlimited")
    print()

    wait_for_backend()
    tail_alerts()
