#!/usr/bin/env python3
"""
CyberSentinel — Fortigate Auto-Blocker
Reads the auto-blocklist from CyberSentinel and pushes deny rules to Fortigate via REST API.

Usage:
  python fortigate_autoblock.py \
    --cs-api http://localhost:8000 \
    --fg-host 192.168.1.1 \
    --fg-token YOUR_API_TOKEN \
    --vdom root

Requirements: pip install requests
"""
import argparse, time, requests, json
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("--cs-api",   default="http://localhost:8000")
parser.add_argument("--fg-host",  required=True, help="Fortigate IP/hostname")
parser.add_argument("--fg-token", required=True, help="Fortigate API token")
parser.add_argument("--vdom",     default="root")
parser.add_argument("--interval", type=int, default=60, help="Sync interval seconds")
parser.add_argument("--dry-run",  action="store_true", help="Print actions without executing")
args = parser.parse_args()

FG_BASE = f"https://{args.fg_host}/api/v2/cmdb"
HEADERS = {"Authorization": f"Bearer {args.fg_token}", "Content-Type": "application/json"}
PARAMS  = {"vdom": args.vdom}

pushed = set()

def get_blocklist():
    r = requests.get(f"{args.cs_api}/api/blocklist", timeout=10)
    return set(r.json().get("ips", []))

def push_to_fortigate(ip: str):
    name = f"CS_BLOCK_{ip.replace('.','_')}"
    # Create address object
    addr_payload = {
        "name": name,
        "type": "ipmask",
        "subnet": f"{ip}/32",
        "comment": f"CyberSentinel auto-block {datetime.utcnow().isoformat()}",
    }
    if args.dry_run:
        print(f"  [DRY RUN] Would create address: {name} for {ip}")
        return True

    r = requests.post(
        f"{FG_BASE}/firewall/address",
        headers=HEADERS, params=PARAMS,
        json=addr_payload, verify=False, timeout=10,
    )
    if r.status_code not in (200, 201):
        print(f"  ✗ Address create failed for {ip}: {r.text[:200]}")
        return False

    # Add to block group (create group if needed)
    grp_r = requests.get(f"{FG_BASE}/firewall/addrgrp/CS_BLOCKLIST",
                         headers=HEADERS, params=PARAMS, verify=False, timeout=10)
    if grp_r.status_code == 200:
        members = grp_r.json().get("results", [{}])[0].get("member", [])
        members.append({"name": name})
        requests.put(f"{FG_BASE}/firewall/addrgrp/CS_BLOCKLIST",
                     headers=HEADERS, params=PARAMS,
                     json={"member": members}, verify=False, timeout=10)
    else:
        requests.post(f"{FG_BASE}/firewall/addrgrp",
                      headers=HEADERS, params=PARAMS,
                      json={"name":"CS_BLOCKLIST","member":[{"name":name}],"comment":"CyberSentinel auto-blocklist"},
                      verify=False, timeout=10)
    print(f"  ✓ Blocked on Fortigate: {ip}")
    return True

print(f"[Fortigate AutoBlocker] Syncing every {args.interval}s → {args.fg_host}")
while True:
    try:
        ips = get_blocklist()
        new = ips - pushed
        if new:
            print(f"[{datetime.utcnow().isoformat()}] {len(new)} new IPs to block")
            for ip in new:
                if push_to_fortigate(ip):
                    pushed.add(ip)
        else:
            print(f"[{datetime.utcnow().isoformat()}] Blocklist up to date ({len(pushed)} IPs)")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    time.sleep(args.interval)
