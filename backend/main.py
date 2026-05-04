"""
CyberSentinel Backend — FastAPI
Handles: log ingestion, IP trail queries, threat intel, stats
"""
import os, json, time, asyncio
from datetime import datetime, timezone
from typing import Optional
import pandas as pd
import redis.asyncio as aioredis
import httpx
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="CyberSentinel API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "demo")
TRAIL_TTL = 60 * 60 * 24 * 30  # 30 days

_redis: Optional[aioredis.Redis] = None

async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    return _redis


# ─── helpers ──────────────────────────────────────────────────────────────────

KNOWN_BAD_SUBNETS = [
    "85.11.182.", "85.11.183.", "85.11.187.",
    "93.152.221.", "198.235.24.", "205.210.31.",
    "195.184.76.", "167.94.146.", "147.185.132.",
]

SEVERITY_MAP = {
    "alert": "critical", "warning": "high",
    "information": "low", "notice": "medium",
}

def extract_src_ip(row: dict) -> Optional[str]:
    for col in ["data.srcip", "data.src_ip", "data.ui", "network.srcIp"]:
        v = row.get(col)
        if v and str(v) not in ("nan", "unknown", "None", ""):
            return str(v)
    return None

def classify_event(row: dict) -> dict:
    rule_desc = str(row.get("rule.description", ""))
    action    = str(row.get("data.action", ""))
    severity  = SEVERITY_MAP.get(str(row.get("data.level", "")), "low")
    threat_type = "unknown"

    if "Login failed" in rule_desc or "login fail" in rule_desc.lower():
        threat_type = "brute_force"
        severity = "high"
    elif "SSH" in rule_desc and ("brute" in rule_desc.lower() or "non-existent" in rule_desc.lower()):
        threat_type = "ssh_bruteforce"
        severity = "high"
    elif "RDP" in rule_desc:
        threat_type = "rdp_relay"
        severity = "critical"
    elif "PostgreSQL" in rule_desc or "mySQL" in rule_desc:
        threat_type = "db_scan"
        severity = "medium"
    elif "VPN" in rule_desc and "fail" in rule_desc.lower():
        threat_type = "vpn_bruteforce"
        severity = "high"
    elif "Dshield" in rule_desc or "Spamhaus" in rule_desc:
        threat_type = "known_malicious"
        severity = "critical"
    elif "Blocked URL" in rule_desc:
        threat_type = "policy_violation"
        severity = "low"
    elif "privilege" in rule_desc.lower():
        threat_type = "privilege_escalation"
        severity = "critical"

    return {"threat_type": threat_type, "severity": severity}


# ─── ingestion ────────────────────────────────────────────────────────────────

async def ingest_log_row(r: aioredis.Redis, row: dict):
    src_ip = extract_src_ip(row)
    if not src_ip:
        return

    classification = classify_event(row)
    ts = row.get("@timestamp", datetime.now(timezone.utc).isoformat())
    try:
        score = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        score = time.time()

    event = {
        "ts":        ts,
        "rule":      str(row.get("rule.description", ""))[:120],
        "action":    str(row.get("data.action", "")),
        "dst_ip":    str(row.get("data.dstip", row.get("data.dest_ip", ""))),
        "dst_port":  str(row.get("data.dstport", row.get("data.dest_port", ""))),
        "country":   str(row.get("data.srccountry", "")),
        "signature": str(row.get("data.alert.signature", ""))[:100],
        "agent":     str(row.get("agent.name", "")),
        "rule_id":   str(row.get("rule.id", "")),
        "mitre":     str(row.get("rule.mitre.id", "")),
        **classification,
    }

    pipe = r.pipeline()
    trail_key = f"trail:{src_ip}"
    pipe.zadd(trail_key, {json.dumps(event): score})
    pipe.expire(trail_key, TRAIL_TTL)

    # Per-IP counters
    pipe.hincrby(f"ipstat:{src_ip}", classification["threat_type"], 1)
    pipe.hincrby(f"ipstat:{src_ip}", "total", 1)
    pipe.expire(f"ipstat:{src_ip}", TRAIL_TTL)

    # Global stats
    pipe.incr("stat:total_logs")
    pipe.incr(f"stat:threat:{classification['threat_type']}")
    if classification["severity"] in ("critical", "high"):
        pipe.sadd("hot_ips", src_ip)
        pipe.expire("hot_ips", 3600)

    # Known bad subnet check
    for subnet in KNOWN_BAD_SUBNETS:
        if src_ip.startswith(subnet):
            pipe.sadd("blocklist:auto", src_ip)
            pipe.expire("blocklist:auto", 86400)
            break

    await pipe.execute()


@app.post("/api/ingest/csv")
async def ingest_csv(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    content = await file.read()
    import io
    df = pd.read_csv(io.BytesIO(content), low_memory=False)
    df = df.fillna("")
    rows = df.to_dict(orient="records")

    async def process():
        r = await get_redis()
        for row in rows:
            await ingest_log_row(r, row)

    background_tasks.add_task(process)
    return {"status": "ingesting", "rows": len(rows)}


@app.post("/api/ingest/log")
async def ingest_single(log: dict):
    r = await get_redis()
    await ingest_log_row(r, log)
    return {"status": "ok"}


# ─── IP trail ─────────────────────────────────────────────────────────────────

@app.get("/api/trail/{ip}")
async def get_trail(ip: str, limit: int = 100):
    r = await get_redis()
    raw = await r.zrange(f"trail:{ip}", -limit, -1)
    events = []
    for item in raw:
        try:
            events.append(json.loads(item))
        except Exception:
            pass
    stats = await r.hgetall(f"ipstat:{ip}")
    return {
        "ip":     ip,
        "events": events,
        "stats":  stats,
        "total":  len(events),
    }


@app.get("/api/trail/{ip}/summary")
async def trail_summary(ip: str):
    r = await get_redis()
    raw = await r.zrange(f"trail:{ip}", 0, -1, withscores=True)
    if not raw:
        return {"ip": ip, "found": False}

    events = []
    for item, score in raw:
        try:
            e = json.loads(item)
            e["_score"] = score
            events.append(e)
        except Exception:
            pass

    threat_types = {}
    severities   = {}
    for e in events:
        threat_types[e.get("threat_type", "?")] = threat_types.get(e.get("threat_type", "?"), 0) + 1
        severities[e.get("severity", "?")] = severities.get(e.get("severity", "?"), 0) + 1

    first_ts = min(e["_score"] for e in events)
    last_ts  = max(e["_score"] for e in events)

    return {
        "ip":          ip,
        "found":       True,
        "total":       len(events),
        "first_seen":  datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat(),
        "last_seen":   datetime.fromtimestamp(last_ts,  tz=timezone.utc).isoformat(),
        "threat_types": threat_types,
        "severities":   severities,
        "is_hot":      await r.sismember("hot_ips", ip),
        "is_blocked":  await r.sismember("blocklist:auto", ip),
    }


# ─── stats ────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    r = await get_redis()
    pipe = r.pipeline()
    pipe.get("stat:total_logs")
    pipe.smembers("hot_ips")
    pipe.smembers("blocklist:auto")
    pipe.keys("trail:*")
    results = await pipe.execute()

    total, hot_ips, blocklist, trail_keys = results
    threat_keys = await r.keys("stat:threat:*")
    threat_counts = {}
    for key in threat_keys:
        val = await r.get(key)
        threat_counts[key.replace("stat:threat:", "")] = int(val or 0)

    return {
        "total_logs":    int(total or 0),
        "unique_ips":    len(trail_keys),
        "hot_ips":       list(hot_ips or []),
        "blocklist":     list(blocklist or []),
        "threat_counts": threat_counts,
    }


@app.get("/api/hot-ips")
async def get_hot_ips():
    r = await get_redis()
    hot = await r.smembers("hot_ips")
    result = []
    for ip in list(hot)[:50]:
        summary = await trail_summary(ip)
        result.append(summary)
    result.sort(key=lambda x: x.get("total", 0), reverse=True)
    return result


# ─── threat intel ─────────────────────────────────────────────────────────────

@app.get("/api/intel/{ip}")
async def get_intel(ip: str):
    r = await get_redis()
    cached = await r.get(f"intel:{ip}")
    if cached:
        return json.loads(cached)

    result = {
        "ip":             ip,
        "is_known_bad":   any(ip.startswith(s) for s in KNOWN_BAD_SUBNETS),
        "in_blocklist":   await r.sismember("blocklist:auto", ip),
        "abuseipdb":      None,
        "source":         "local",
    }

    if ABUSEIPDB_KEY and ABUSEIPDB_KEY != "demo":
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    result["abuseipdb"] = {
                        "score":      data.get("abuseConfidenceScore", 0),
                        "country":    data.get("countryCode", ""),
                        "isp":        data.get("isp", ""),
                        "reports":    data.get("totalReports", 0),
                        "is_tor":     data.get("isTor", False),
                        "is_public":  data.get("isPublic", True),
                    }
                    result["source"] = "abuseipdb"
        except Exception:
            pass

    await r.setex(f"intel:{ip}", 900, json.dumps(result))  # cache 15 min
    return result


# ─── blocklist ────────────────────────────────────────────────────────────────

@app.get("/api/blocklist")
async def get_blocklist():
    r = await get_redis()
    ips = await r.smembers("blocklist:auto")
    return {"count": len(ips), "ips": list(ips)}


@app.post("/api/blocklist/add")
async def add_to_blocklist(payload: dict):
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(400, "ip required")
    r = await get_redis()
    await r.sadd("blocklist:manual", ip)
    return {"status": "blocked", "ip": ip}


@app.delete("/api/blocklist/{ip}")
async def remove_from_blocklist(ip: str):
    r = await get_redis()
    await r.srem("blocklist:auto", ip)
    await r.srem("blocklist:manual", ip)
    return {"status": "unblocked", "ip": ip}


# ─── search ───────────────────────────────────────────────────────────────────

@app.get("/api/search")
async def search_ip(q: str):
    r = await get_redis()
    keys = await r.keys(f"trail:{q}*")
    ips  = [k.replace("trail:", "") for k in keys[:20]]
    results = []
    for ip in ips:
        s = await trail_summary(ip)
        results.append(s)
    return results


@app.get("/api/health")
async def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}
