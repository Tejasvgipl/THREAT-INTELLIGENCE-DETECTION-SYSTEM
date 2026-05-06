"""
CyberSentinel Backend — FastAPI v2.0
Handles: log ingestion, IP trail, threat intel, stats, 24 behavioural baselines
"""
import os, json, time, statistics
from datetime import datetime, timezone
from typing import Optional
import pandas as pd
import redis.asyncio as aioredis
import httpx
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="CyberSentinel API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

REDIS_HOST    = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT    = int(os.getenv("REDIS_PORT", 6379))
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "demo")
TRAIL_TTL     = 60 * 60 * 24 * 30
BASELINE_TTL  = 60 * 60 * 24 * 90
ALERT_TTL     = 60 * 60 * 24 * 7
MIN_EVENTS_FOR_BASELINE = 10
VOLUME_SPIKE_MULTIPLIER = 3

_redis: Optional[aioredis.Redis] = None

async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    return _redis

# ── constants ─────────────────────────────────────────────────────────────────

KNOWN_BAD_SUBNETS = [
    "85.11.182.","85.11.183.","85.11.187.",
    "93.152.221.","198.235.24.","205.210.31.",
    "195.184.76.","167.94.146.","147.185.132.",
]

SENSITIVE_PORTS = {
    "22":"SSH","23":"Telnet","3389":"RDP",
    "3306":"MySQL","5432":"PostgreSQL","1433":"MSSQL",
    "27017":"MongoDB","6379":"Redis","9200":"Elasticsearch",
    "5900":"VNC","445":"SMB","139":"NetBIOS",
}

INTERNAL_RANGES = (
    "10.","172.16.","172.17.","172.18.","172.19.",
    "172.20.","172.21.","172.22.","172.23.","172.24.",
    "172.25.","172.26.","172.27.","172.28.","172.29.",
    "172.30.","172.31.","192.168.",
)

SEVERITY_MAP = {
    "alert":"critical","warning":"high",
    "information":"low","notice":"medium",
}

# ── helpers ───────────────────────────────────────────────────────────────────

def extract_src_ip(row: dict) -> Optional[str]:
    for col in [
        "data.srcip", "data.src_ip", "data.ui",
        "network.srcIp", "network.source.ip",
        "data.win.eventdata.sourceIp", "data.win.eventdata.ipAddress",
        "source.ip", "src_ip", "srcip", "agent.ip",
    ]:
        v = row.get(col)
        if v and str(v).strip().lower() not in ("nan","unknown","none",""):
            return str(v)
    return None

def classify_event(row: dict) -> dict:
    rule_desc   = str(row.get("rule.description",""))
    raw_level    = str(row.get("data.level", row.get("rule.level",""))).lower()
    severity     = SEVERITY_MAP.get(raw_level, "low")
    if raw_level.isdigit():
        lvl = int(raw_level)
        severity = "critical" if lvl >= 12 else "high" if lvl >= 8 else "medium" if lvl >= 4 else "low"
    threat_type = "unknown"

    if "Login failed" in rule_desc or "login fail" in rule_desc.lower():
        threat_type, severity = "brute_force", "high"
    elif "SSH" in rule_desc and ("brute" in rule_desc.lower() or "non-existent" in rule_desc.lower()):
        threat_type, severity = "ssh_bruteforce", "high"
    elif "RDP" in rule_desc:
        threat_type, severity = "rdp_relay", "critical"
    elif "PostgreSQL" in rule_desc or "MySQL" in rule_desc or "mySQL" in rule_desc:
        threat_type, severity = "db_scan", "medium"
    elif "VPN" in rule_desc and "fail" in rule_desc.lower():
        threat_type, severity = "vpn_bruteforce", "high"
    elif "Dshield" in rule_desc or "Spamhaus" in rule_desc:
        threat_type, severity = "known_malicious", "critical"
    elif "Blocked URL" in rule_desc:
        threat_type, severity = "policy_violation", "low"
    elif "privilege" in rule_desc.lower():
        threat_type, severity = "privilege_escalation", "critical"
    elif "login" in rule_desc.lower() and "success" in rule_desc.lower():
        threat_type, severity = "login_success", "low"

    return {"threat_type": threat_type, "severity": severity}

def is_internal(ip: str) -> bool:
    return any(ip.startswith(r) for r in INTERNAL_RANGES)

def get_subnet24(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ""

# ── baseline builder ──────────────────────────────────────────────────────────

async def build_baseline(r: aioredis.Redis, ip: str):
    raw = await r.zrange(f"trail:{ip}", 0, -1, withscores=True)
    if len(raw) < MIN_EVENTS_FOR_BASELINE:
        return

    events = []
    for item, score in raw:
        try:
            e = json.loads(item)
            e["_ts"] = score
            events.append(e)
        except Exception:
            pass

    if not events:
        return

    ports, dst_ips, subnets, countries = {}, {}, {}, {}
    hours, weekdays, rule_groups       = {}, {}, {}
    daily_counts: dict[str, int]       = {}
    rule_levels  = []
    success_cnt  = 0
    fail_cnt     = 0

    for e in events:
        p = str(e.get("dst_port","")).strip()
        if p and p not in ("","None","nan"):
            ports[p] = ports.get(p,0) + 1

        dip = str(e.get("dst_ip","")).strip()
        if dip and dip not in ("","None","nan"):
            dst_ips[dip] = dst_ips.get(dip,0) + 1
            sn = get_subnet24(dip)
            if sn:
                subnets[sn] = subnets.get(sn,0) + 1

        c = str(e.get("country","")).strip()
        if c and c not in ("","None","nan"):
            countries[c] = countries.get(c,0) + 1

        try:
            dt  = datetime.fromtimestamp(e["_ts"], tz=timezone.utc)
            h   = str(dt.hour)
            wd  = str(dt.weekday())
            day = dt.strftime("%Y-%m-%d")
            hours[h]   = hours.get(h,0) + 1
            weekdays[wd] = weekdays.get(wd,0) + 1
            daily_counts[day] = daily_counts.get(day,0) + 1
        except Exception:
            pass

        tt = str(e.get("threat_type","unknown"))
        rule_groups[tt] = rule_groups.get(tt,0) + 1

        sev_score = {"critical":4,"high":3,"medium":2,"low":1}.get(e.get("severity","low"),1)
        rule_levels.append(sev_score)

        if e.get("threat_type") == "login_success":
            success_cnt += 1
        elif e.get("threat_type") in ("brute_force","ssh_bruteforce","vpn_bruteforce"):
            fail_cnt += 1

    avg_daily = sum(daily_counts.values()) / max(len(daily_counts),1)
    avg_sev   = sum(rule_levels) / max(len(rule_levels),1)

    baseline = {
        "ip":               ip,
        "built_at":         datetime.now(timezone.utc).isoformat(),
        "event_count":      len(events),
        "usual_ports":      ports,
        "usual_dst_ips":    dst_ips,
        "usual_subnets":    subnets,
        "usual_countries":  countries,
        "usual_hours":      hours,
        "usual_weekdays":   weekdays,
        "usual_rule_groups":rule_groups,
        "avg_daily_events": round(avg_daily,2),
        "avg_severity_score": round(avg_sev,3),
        "total_successes":  success_cnt,
        "total_failures":   fail_cnt,
        "daily_counts":     daily_counts,
    }

    await r.set(f"baseline:{ip}", json.dumps(baseline))
    await r.expire(f"baseline:{ip}", BASELINE_TTL)

# ── deviation detector ────────────────────────────────────────────────────────

async def detect_deviations(r: aioredis.Redis, ip: str, event: dict, ts: float) -> list:
    raw = await r.get(f"baseline:{ip}")
    if not raw:
        return []

    b      = json.loads(raw)
    alerts = []

    def alert(atype, message, severity="high", details=None):
        return {
            "ip": ip, "type": atype, "message": message,
            "severity": severity,
            "ts": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
            "details": details or {},
        }

    # 1. PORT SHIFT
    port = str(event.get("dst_port","")).strip()
    if port and port not in ("","None","nan") and b.get("usual_ports"):
        if port not in b["usual_ports"]:
            sev = "critical" if port in SENSITIVE_PORTS else "high"
            alerts.append(alert("port_shift",
                f"New port {port} ({SENSITIVE_PORTS.get(port,'unknown')}) never seen before",
                sev, {"new_port":port,"known_ports":list(b["usual_ports"].keys())[:5]}))

    # 2. SENSITIVE PORT TARGETING
    if port in SENSITIVE_PORTS:
        if not b.get("usual_ports") or port not in b["usual_ports"]:
            alerts.append(alert("sensitive_port_targeted",
                f"First hit on sensitive port {port} ({SENSITIVE_PORTS[port]})",
                "critical", {"port":port,"service":SENSITIVE_PORTS[port]}))

    # 3. NEW DESTINATION SUBNET
    dip = str(event.get("dst_ip","")).strip()
    if dip and dip not in ("","None","nan"):
        sn = get_subnet24(dip)
        if sn and b.get("usual_subnets") and sn not in b["usual_subnets"]:
            alerts.append(alert("new_subnet_reached",
                f"Reaching new subnet {sn}.x never contacted before",
                "high", {"new_subnet":sn}))

    # 4. INTERNAL HOST REACHED
    if dip and is_internal(dip) and not is_internal(ip):
        alerts.append(alert("internal_host_reached",
            f"External IP now reaching internal host {dip}",
            "critical", {"internal_dst":dip}))

    # 5. TARGET SHIFT — unique dst IPs spiking
    if b.get("usual_dst_ips"):
        usual_unique = len(b["usual_dst_ips"])
        recent_raw   = await r.zrange(f"trail:{ip}", -50, -1)
        recent_dsts  = set()
        for item in recent_raw:
            try:
                e2 = json.loads(item)
                d  = str(e2.get("dst_ip","")).strip()
                if d and d not in ("","None","nan"):
                    recent_dsts.add(d)
            except Exception:
                pass
        if len(recent_dsts) > usual_unique * 2 and len(recent_dsts) > 5:
            alerts.append(alert("target_shift",
                f"Now targeting {len(recent_dsts)} unique IPs — baseline was {usual_unique}",
                "critical", {"current_unique":len(recent_dsts),"baseline_unique":usual_unique}))

    # 6. GEOGRAPHIC SHIFT
    country = str(event.get("country","")).strip()
    if country and country not in ("","None","nan") and b.get("usual_countries"):
        if country not in b["usual_countries"] and len(b["usual_countries"]) >= 2:
            alerts.append(alert("country_shift",
                f"Now from {country} — usual: {', '.join(list(b['usual_countries'].keys())[:3])}",
                "medium", {"new_country":country,"usual":list(b["usual_countries"].keys())[:3]}))

    # 7. OFF-HOURS ACTIVITY
    try:
        dt   = datetime.fromtimestamp(ts, tz=timezone.utc)
        hour = dt.hour
        wday = dt.weekday()

        if b.get("usual_hours") and str(hour) not in b["usual_hours"] and len(b["usual_hours"]) >= 5:
            alerts.append(alert("off_hours_activity",
                f"Activity at {hour:02d}:00 UTC — this hour never seen before",
                "high", {"hour":hour,"usual_hours":list(b["usual_hours"].keys())}))

        # 8. WEEKEND ANOMALY
        if b.get("usual_weekdays"):
            usual_wdays = [int(w) for w in b["usual_weekdays"].keys()]
            if wday >= 5 and all(w < 5 for w in usual_wdays):
                alerts.append(alert("weekend_anomaly",
                    f"Activity on {'Saturday' if wday==5 else 'Sunday'} — only ever weekdays before",
                    "high", {"weekday":wday}))
    except Exception:
        pass

    # 9. VOLUME SPIKE
    try:
        day_key   = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
        today_cnt = await r.hincrby(f"daily:{ip}", day_key, 1)
        await r.expire(f"daily:{ip}", BASELINE_TTL)
        avg_daily = b.get("avg_daily_events", 0)
        if avg_daily > 5 and today_cnt > avg_daily * VOLUME_SPIKE_MULTIPLIER:
            alerts.append(alert("volume_spike",
                f"Today: {today_cnt} events — avg: {avg_daily}/day (x{round(today_cnt/avg_daily,1)})",
                "critical", {"today":today_cnt,"avg_daily":avg_daily}))
    except Exception:
        pass

    # 10. NEW RULE / THREAT TYPE
    tt = event.get("threat_type","unknown")
    if b.get("usual_rule_groups") and tt not in b["usual_rule_groups"] and tt != "unknown":
        sev = "critical" if tt in ("privilege_escalation","rdp_relay","known_malicious") else "high"
        alerts.append(alert("new_rule_category",
            f"First time triggering '{tt}' — behaviour escalation",
            sev, {"new_type":tt,"usual":list(b["usual_rule_groups"].keys())}))

    # 11. RULE ESCALATION
    if b.get("avg_severity_score"):
        new_sev = {"critical":4,"high":3,"medium":2,"low":1}.get(event.get("severity","low"),1)
        if new_sev > b["avg_severity_score"] + 1.5:
            alerts.append(alert("rule_escalation",
                f"Severity jumped to {event.get('severity')} — baseline avg was {b['avg_severity_score']:.1f}",
                "high", {"new_severity":event.get("severity"),"baseline_avg":b["avg_severity_score"]}))

    # 12. FIRST SUCCESS AFTER FAILURES
    if tt == "login_success":
        if b.get("total_failures",0) >= 5 and b.get("total_successes",0) == 0:
            alerts.append(alert("first_success_after_failures",
                f"FIRST LOGIN SUCCESS after {b['total_failures']} prior failures — possible breach",
                "critical", {"prior_failures":b["total_failures"]}))

    # 13. AUTOMATED TOOL (inter-event interval collapse)
    recent_ws = await r.zrange(f"trail:{ip}", -20, -1, withscores=True)
    if len(recent_ws) >= 10:
        recent_ts_list = [sc for _, sc in recent_ws]
        ivs = [recent_ts_list[i+1]-recent_ts_list[i] for i in range(len(recent_ts_list)-1)]
        if ivs:
            avg_iv = sum(ivs)/len(ivs)
            std_iv = statistics.stdev(ivs) if len(ivs) > 1 else 0
            if avg_iv < 0.5 and std_iv < 0.1:
                alerts.append(alert("automated_tool_detected",
                    f"Events every {avg_iv:.3f}s std={std_iv:.4f} — automated scanner",
                    "high", {"avg_interval":round(avg_iv,4),"std_interval":round(std_iv,4)}))

    # 14. DORMANT IP REACTIVATION
    if b.get("daily_counts"):
        last_day_str = max(b["daily_counts"].keys())
        try:
            last_day = datetime.strptime(last_day_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            now      = datetime.fromtimestamp(ts, tz=timezone.utc)
            gap_days = (now - last_day).days
            if gap_days >= 7:
                alerts.append(alert("dormant_ip_reactivated",
                    f"IP was dormant {gap_days} days — sudden reactivation",
                    "high", {"gap_days":gap_days,"last_seen":last_day_str}))
        except Exception:
            pass

    return alerts


async def save_alerts(r: aioredis.Redis, ip: str, alerts: list):
    if not alerts:
        return
    pipe = r.pipeline()
    for a in alerts:
        key = f"alert:{ip}:{a['type']}"
        pipe.set(key, json.dumps(a))
        pipe.expire(key, ALERT_TTL)
        pipe.incr("stat:total_alerts")
        pipe.incr(f"stat:alert_type:{a['type']}")
        if a["severity"] == "critical":
            pipe.sadd("critical_alerts", ip)
            pipe.expire("critical_alerts", 3600)
    await pipe.execute()


# ── ingestion ─────────────────────────────────────────────────────────────────

async def ingest_log_row(r: aioredis.Redis, row: dict):
    src_ip = extract_src_ip(row)
    if not src_ip:
        return

    classification = classify_event(row)
    ts = row.get("@timestamp", datetime.now(timezone.utc).isoformat())
    try:
        score = datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
    except Exception:
        score = time.time()

    event = {
        "ts":        ts,
        "rule":      str(row.get("rule.description",""))[:120],
        "action":    str(row.get("data.action","")),
        "dst_ip":    str(row.get("data.dstip", row.get("data.dest_ip", row.get("network.destIp", row.get("data.win.eventdata.destinationIp",""))))),
        "dst_port":  str(row.get("data.dstport", row.get("data.dest_port", row.get("network.destPort", row.get("data.win.eventdata.destinationPort",""))))),
        "country":   str(row.get("data.srccountry","")),
        "signature": str(row.get("data.alert.signature",""))[:100],
        "agent":     str(row.get("agent.name","")),
        "rule_id":   str(row.get("rule.id","")),
        "mitre":     str(row.get("rule.mitre.id","")),
        "username":  str(row.get("data.user", row.get("data.win.eventdata.user",""))),
        "useragent": str(row.get("data.http.http_user_agent","")),
        **classification,
    }

    pipe = r.pipeline()
    pipe.zadd(f"trail:{src_ip}", {json.dumps(event): score})
    pipe.expire(f"trail:{src_ip}", TRAIL_TTL)
    pipe.hincrby(f"ipstat:{src_ip}", classification["threat_type"], 1)
    pipe.hincrby(f"ipstat:{src_ip}", "total", 1)
    pipe.expire(f"ipstat:{src_ip}", TRAIL_TTL)
    pipe.incr("stat:total_logs")
    pipe.incr(f"stat:threat:{classification['threat_type']}")
    if classification["severity"] in ("critical","high"):
        pipe.sadd("hot_ips", src_ip)
        pipe.expire("hot_ips", 3600)
    for subnet in KNOWN_BAD_SUBNETS:
        if src_ip.startswith(subnet):
            pipe.sadd("blocklist:auto", src_ip)
            pipe.expire("blocklist:auto", 86400)
            break
    await pipe.execute()

    # Baseline deviation check
    alerts = await detect_deviations(r, src_ip, event, score)
    if alerts:
        await save_alerts(r, src_ip, alerts)

    # Rebuild baseline every 50 events
    total = await r.hget(f"ipstat:{src_ip}", "total")
    if total and int(total) % 50 == 0:
        await build_baseline(r, src_ip)


@app.post("/api/ingest/csv")
async def ingest_csv(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    import io
    content = await file.read()
    df = pd.read_csv(io.BytesIO(content), low_memory=False).fillna("")
    rows = df.to_dict(orient="records")

    async def process():
        r = await get_redis()
        for row in rows:
            await ingest_log_row(r, row)
        keys = await r.keys("trail:*")
        for key in keys:
            await build_baseline(r, key.replace("trail:",""))

    background_tasks.add_task(process)
    return {"status":"ingesting","rows":len(rows)}


@app.post("/api/ingest/bulk")
async def ingest_bulk(background_tasks: BackgroundTasks, logs: list):
    async def process():
        r = await get_redis()
        for log in logs:
            await ingest_log_row(r, log)
    background_tasks.add_task(process)
    return {"status":"ingesting","count":len(logs)}


@app.post("/api/ingest/log")
async def ingest_single(log: dict):
    r = await get_redis()
    await ingest_log_row(r, log)
    return {"status":"ok"}


# ── IP trail ──────────────────────────────────────────────────────────────────

@app.get("/api/trail/{ip}")
async def get_trail(ip: str, limit: int = 100):
    r   = await get_redis()
    raw = await r.zrange(f"trail:{ip}", -limit, -1)
    events = []
    for item in raw:
        try:
            events.append(json.loads(item))
        except Exception:
            pass
    stats = await r.hgetall(f"ipstat:{ip}")
    return {"ip":ip,"events":events,"stats":stats,"total":len(events)}


@app.get("/api/trail/{ip}/summary")
async def trail_summary(ip: str):
    r   = await get_redis()
    raw = await r.zrange(f"trail:{ip}", 0, -1, withscores=True)
    if not raw:
        return {"ip":ip,"found":False}

    events = []
    for item, score in raw:
        try:
            e = json.loads(item)
            e["_score"] = score
            events.append(e)
        except Exception:
            pass

    threat_types: dict = {}
    severities: dict   = {}
    for e in events:
        k = e.get("threat_type","?")
        threat_types[k] = threat_types.get(k,0) + 1
        s = e.get("severity","?")
        severities[s]   = severities.get(s,0) + 1

    first_ts = min(e["_score"] for e in events)
    last_ts  = max(e["_score"] for e in events)

    return {
        "ip":           ip,
        "found":        True,
        "total":        len(events),
        "first_seen":   datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat(),
        "last_seen":    datetime.fromtimestamp(last_ts,  tz=timezone.utc).isoformat(),
        "threat_types": threat_types,
        "severities":   severities,
        "is_hot":       await r.sismember("hot_ips", ip),
        "is_blocked":   await r.sismember("blocklist:auto", ip),
    }


# ── baselines ─────────────────────────────────────────────────────────────────

@app.get("/api/baseline/{ip}")
async def get_baseline(ip: str):
    r   = await get_redis()
    raw = await r.get(f"baseline:{ip}")
    if not raw:
        return {"ip":ip,"found":False,"message":"No baseline yet — needs 10+ events"}
    return {"ip":ip,"found":True,"baseline":json.loads(raw)}


@app.post("/api/baseline/{ip}/build")
async def force_build_baseline(ip: str):
    r = await get_redis()
    await build_baseline(r, ip)
    raw = await r.get(f"baseline:{ip}")
    if raw:
        return {"status":"built","ip":ip,"baseline":json.loads(raw)}
    return {"status":"not_enough_data","ip":ip}


@app.post("/api/baseline/build-all")
async def build_all_baselines():
    r    = await get_redis()
    keys = await r.keys("trail:*")
    for key in keys:
        await build_baseline(r, key.replace("trail:",""))
    return {"status":"done","baselines_built":len(keys)}


# ── alerts ────────────────────────────────────────────────────────────────────

@app.get("/api/alerts")
async def get_alerts(severity: str = None, limit: int = 100):
    r    = await get_redis()
    keys = await r.keys("alert:*")
    alerts = []
    for key in keys[:500]:
        val = await r.get(key)
        if val:
            try:
                a = json.loads(val)
                if severity and a.get("severity") != severity:
                    continue
                alerts.append(a)
            except Exception:
                pass
    alerts.sort(key=lambda x: x.get("ts",""), reverse=True)
    return {"alerts":alerts[:limit],"total":len(alerts)}


@app.get("/api/alerts/{ip}")
async def get_ip_alerts(ip: str):
    r    = await get_redis()
    keys = await r.keys(f"alert:{ip}:*")
    alerts = []
    for key in keys:
        val = await r.get(key)
        if val:
            try:
                alerts.append(json.loads(val))
            except Exception:
                pass
    alerts.sort(key=lambda x: x.get("ts",""), reverse=True)
    return {"ip":ip,"alerts":alerts,"total":len(alerts)}


# ── stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    r = await get_redis()
    pipe = r.pipeline()
    pipe.get("stat:total_logs")
    pipe.smembers("hot_ips")
    pipe.smembers("blocklist:auto")
    pipe.keys("trail:*")
    pipe.get("stat:total_alerts")
    pipe.smembers("critical_alerts")
    results = await pipe.execute()
    total, hot_ips, blocklist, trail_keys, total_alerts, critical_ips = results

    threat_keys = await r.keys("stat:threat:*")
    threat_counts = {}
    for key in threat_keys:
        val = await r.get(key)
        threat_counts[key.replace("stat:threat:","")] = int(val or 0)

    alert_keys = await r.keys("stat:alert_type:*")
    alert_counts = {}
    for key in alert_keys:
        val = await r.get(key)
        alert_counts[key.replace("stat:alert_type:","")] = int(val or 0)

    return {
        "total_logs":       int(total or 0),
        "unique_ips":       len(trail_keys),
        "hot_ips":          list(hot_ips or []),
        "blocklist":        list(blocklist or []),
        "threat_counts":    threat_counts,
        "total_alerts":     int(total_alerts or 0),
        "critical_ips":     list(critical_ips or []),
        "alert_type_counts":alert_counts,
    }


@app.get("/api/hot-ips")
async def get_hot_ips():
    r   = await get_redis()
    hot = await r.smembers("hot_ips")
    result = []
    for ip in list(hot)[:50]:
        summary = await trail_summary(ip)
        result.append(summary)
    result.sort(key=lambda x: x.get("total",0), reverse=True)
    return result


# ── threat intel ──────────────────────────────────────────────────────────────

@app.get("/api/intel/{ip}")
async def get_intel(ip: str):
    r      = await get_redis()
    cached = await r.get(f"intel:{ip}")
    if cached:
        return json.loads(cached)

    result = {
        "ip":           ip,
        "is_known_bad": any(ip.startswith(s) for s in KNOWN_BAD_SUBNETS),
        "in_blocklist": await r.sismember("blocklist:auto", ip),
        "abuseipdb":    None,
        "source":       "local",
    }

    if ABUSEIPDB_KEY and ABUSEIPDB_KEY != "demo":
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress":ip,"maxAgeInDays":90},
                    headers={"Key":ABUSEIPDB_KEY,"Accept":"application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data",{})
                    result["abuseipdb"] = {
                        "score":     data.get("abuseConfidenceScore",0),
                        "country":   data.get("countryCode",""),
                        "isp":       data.get("isp",""),
                        "reports":   data.get("totalReports",0),
                        "is_tor":    data.get("isTor",False),
                        "is_public": data.get("isPublic",True),
                    }
                    result["source"] = "abuseipdb"
        except Exception:
            pass

    await r.setex(f"intel:{ip}", 900, json.dumps(result))
    return result


# ── blocklist ─────────────────────────────────────────────────────────────────

@app.get("/api/blocklist")
async def get_blocklist():
    r   = await get_redis()
    ips = await r.smembers("blocklist:auto")
    man = await r.smembers("blocklist:manual")
    return {"count":len(ips)+len(man),"ips":list(ips|man)}


@app.post("/api/blocklist/add")
async def add_to_blocklist(payload: dict):
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(400,"ip required")
    r = await get_redis()
    await r.sadd("blocklist:manual", ip)
    return {"status":"blocked","ip":ip}


@app.delete("/api/blocklist/{ip}")
async def remove_from_blocklist(ip: str):
    r = await get_redis()
    await r.srem("blocklist:auto", ip)
    await r.srem("blocklist:manual", ip)
    return {"status":"unblocked","ip":ip}


# ── search + health ───────────────────────────────────────────────────────────

@app.get("/api/search")
async def search_ip(q: str):
    r    = await get_redis()
    keys = await r.keys(f"trail:{q}*")
    ips  = [k.replace("trail:","") for k in keys[:20]]
    return [await trail_summary(ip) for ip in ips]


@app.get("/api/health")
async def health():
    return {"status":"ok","version":"2.0.0","time":datetime.now(timezone.utc).isoformat()}
