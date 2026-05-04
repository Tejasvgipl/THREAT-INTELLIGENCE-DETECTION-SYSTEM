"""
CyberSentinel ML Engine
- Isolation Forest: anomaly / spray detection per IP
- Subnet clustering: NetworkX graph of coordinated attackers
- Risk scorer: combined score for each IP
"""
import os, json, asyncio, joblib
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
import redis.asyncio as aioredis
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import networkx as nx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="CyberSentinel ML Engine", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

REDIS_HOST  = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT  = int(os.getenv("REDIS_PORT", 6379))
MODEL_DIR   = Path("/app/models")
MODEL_DIR.mkdir(exist_ok=True)

_redis = None

async def get_redis():
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    return _redis


# ─── feature extraction ───────────────────────────────────────────────────────

async def extract_ip_features(r: aioredis.Redis, ip: str) -> dict:
    """Pull trail for one IP and compute ML features."""
    raw = await r.zrange(f"trail:{ip}", 0, -1, withscores=True)
    if not raw:
        return {}

    events = []
    for item, score in raw:
        try:
            e = json.loads(item)
            e["_score"] = score
            events.append(e)
        except Exception:
            pass

    if not events:
        return {}

    timestamps = sorted(e["_score"] for e in events)
    n = len(events)

    # Inter-event intervals
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    avg_interval   = float(np.mean(intervals))   if intervals else 0
    min_interval   = float(np.min(intervals))    if intervals else 0
    std_interval   = float(np.std(intervals))    if intervals else 0

    # Threat composition
    threat_counts = {}
    severities    = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    dst_ips       = set()
    dst_ports     = set()

    for e in events:
        tt = e.get("threat_type", "unknown")
        threat_counts[tt] = threat_counts.get(tt, 0) + 1
        sev = e.get("severity", "low")
        if sev in severities:
            severities[sev] += 1
        if e.get("dst_ip"):
            dst_ips.add(e["dst_ip"])
        if e.get("dst_port"):
            dst_ports.add(e["dst_port"])

    window_seconds = (max(timestamps) - min(timestamps)) + 1
    event_rate     = n / window_seconds * 60  # events per minute

    return {
        "ip":              ip,
        "n_events":        n,
        "event_rate_pm":   round(event_rate, 3),
        "avg_interval_s":  round(avg_interval, 3),
        "min_interval_s":  round(min_interval, 3),
        "std_interval_s":  round(std_interval, 3),
        "unique_dst_ips":  len(dst_ips),
        "unique_dst_ports":len(dst_ports),
        "pct_critical":    round(severities["critical"] / n, 3),
        "pct_high":        round(severities["high"] / n, 3),
        "brute_force_cnt": threat_counts.get("brute_force", 0),
        "ssh_bf_cnt":      threat_counts.get("ssh_bruteforce", 0),
        "rdp_cnt":         threat_counts.get("rdp_relay", 0),
        "db_scan_cnt":     threat_counts.get("db_scan", 0),
        "known_bad_cnt":   threat_counts.get("known_malicious", 0),
        "window_minutes":  round(window_seconds / 60, 2),
    }

FEATURE_COLS = [
    "n_events", "event_rate_pm", "avg_interval_s", "min_interval_s",
    "std_interval_s", "unique_dst_ips", "unique_dst_ports",
    "pct_critical", "pct_high", "brute_force_cnt", "ssh_bf_cnt",
    "rdp_cnt", "db_scan_cnt", "known_bad_cnt",
]


# ─── train / load model ───────────────────────────────────────────────────────

async def get_all_ip_features(r: aioredis.Redis):
    keys = await r.keys("trail:*")
    ips  = [k.replace("trail:", "") for k in keys]
    features = []
    for ip in ips:
        f = await extract_ip_features(r, ip)
        if f:
            features.append(f)
    return features

def train_isolation_forest(features: list) -> tuple:
    if len(features) < 5:
        return None, None
    X = np.array([[f.get(c, 0) for c in FEATURE_COLS] for f in features])
    scaler = StandardScaler()
    Xs     = scaler.fit_transform(X)
    model  = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
    model.fit(Xs)
    return model, scaler

@app.post("/api/ml/train")
async def train_model():
    r = await get_redis()
    features = await get_all_ip_features(r)
    if len(features) < 5:
        return {"status": "not_enough_data", "ip_count": len(features)}

    model, scaler = train_isolation_forest(features)
    if model is None:
        return {"status": "training_failed"}

    joblib.dump(model,  MODEL_DIR / "isolation_forest.pkl")
    joblib.dump(scaler, MODEL_DIR / "scaler.pkl")

    scores = []
    X = np.array([[f.get(c, 0) for c in FEATURE_COLS] for f in features])
    Xs = scaler.transform(X)
    raw_scores = model.decision_function(Xs)

    for i, f in enumerate(features):
        score = float(raw_scores[i])
        anomaly = bool(model.predict(Xs[i:i+1])[0] == -1)
        await r.setex(
            f"ml:score:{f['ip']}",
            3600,
            json.dumps({"anomaly_score": round(score, 4), "is_anomaly": anomaly})
        )
        if anomaly:
            scores.append({"ip": f["ip"], "score": round(score, 4)})

    return {
        "status":     "trained",
        "ip_count":   len(features),
        "anomalies":  len(scores),
        "top_anomalies": sorted(scores, key=lambda x: x["score"])[:10],
    }


# ─── score single IP ──────────────────────────────────────────────────────────

@app.get("/api/ml/score/{ip}")
async def score_ip(ip: str):
    r = await get_redis()

    cached = await r.get(f"ml:score:{ip}")
    if cached:
        data = json.loads(cached)
        data["ip"] = ip
        data["source"] = "cached"
        return data

    features = await extract_ip_features(r, ip)
    if not features:
        return {"ip": ip, "found": False}

    model_path  = MODEL_DIR / "isolation_forest.pkl"
    scaler_path = MODEL_DIR / "scaler.pkl"

    if not model_path.exists():
        return {
            "ip": ip,
            "features": features,
            "anomaly_score": None,
            "note": "Model not trained yet. POST /api/ml/train first.",
        }

    model  = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    x = np.array([[features.get(c, 0) for c in FEATURE_COLS]])
    xs = scaler.transform(x)
    score    = float(model.decision_function(xs)[0])
    is_anom  = bool(model.predict(xs)[0] == -1)

    # Simple risk score 0-100
    risk = max(0, min(100, int((1 - (score + 0.5)) * 100)))

    result = {
        "ip":            ip,
        "anomaly_score": round(score, 4),
        "risk_score":    risk,
        "is_anomaly":    is_anom,
        "features":      features,
        "source":        "live",
    }
    await r.setex(f"ml:score:{ip}", 300, json.dumps({k: v for k, v in result.items() if k != "ip"}))
    return result


# ─── subnet clustering ────────────────────────────────────────────────────────

@app.get("/api/ml/clusters")
async def get_clusters():
    r = await get_redis()
    keys = await r.keys("trail:*")
    ips  = [k.replace("trail:", "") for k in keys]

    G = nx.Graph()

    # Group IPs by /24 subnet
    subnets: dict[str, list] = {}
    for ip in ips:
        parts = ip.split(".")
        if len(parts) == 4:
            subnet = ".".join(parts[:3])
            subnets.setdefault(subnet, []).append(ip)

    for subnet, subnet_ips in subnets.items():
        if len(subnet_ips) > 1:
            for ip in subnet_ips:
                G.add_node(ip, subnet=subnet)
            for i in range(len(subnet_ips)):
                for j in range(i+1, len(subnet_ips)):
                    G.add_edge(subnet_ips[i], subnet_ips[j], weight=1)

    clusters = []
    for component in nx.connected_components(G):
        if len(component) > 1:
            ips_list   = list(component)
            subnet_key = ".".join(ips_list[0].split(".")[:3]) + ".x/24"
            total_events = 0
            for ip in ips_list:
                stat = await r.hget(f"ipstat:{ip}", "total")
                total_events += int(stat or 0)

            clusters.append({
                "subnet":       subnet_key,
                "ip_count":     len(ips_list),
                "ips":          ips_list[:20],
                "total_events": total_events,
                "threat_level": "critical" if total_events > 500 else "high" if total_events > 100 else "medium",
            })

    clusters.sort(key=lambda x: x["total_events"], reverse=True)
    return {"clusters": clusters, "total_subnets": len(subnets)}


# ─── anomaly list ─────────────────────────────────────────────────────────────

@app.get("/api/ml/anomalies")
async def list_anomalies():
    r = await get_redis()
    keys = await r.keys("ml:score:*")
    anomalies = []
    for key in keys:
        val = await r.get(key)
        if val:
            data = json.loads(val)
            if data.get("is_anomaly"):
                ip = key.replace("ml:score:", "")
                anomalies.append({"ip": ip, **data})
    anomalies.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return {"anomalies": anomalies}


@app.get("/api/ml/health")
async def ml_health():
    model_ready = (MODEL_DIR / "isolation_forest.pkl").exists()
    return {
        "status":      "ok",
        "model_ready": model_ready,
        "time":        datetime.now(timezone.utc).isoformat(),
    }
