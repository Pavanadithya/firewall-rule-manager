import json
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from .db import connect
from .detection_engine import detect
from .parsers import normalize_zeek, normalize_suricata
from .schemas import EventIn, StatusIn

app = FastAPI(title="NetShield SOC", version="1.0.0")
UI = Path(__file__).resolve().parent / "static" / "index.html"


def insert_event(evt: dict) -> int:
    conn = connect()
    cur = conn.execute("""INSERT INTO events (ts,source,event_type,src_ip,dst_ip,src_port,dst_port,proto,username,uri,query,bytes,raw_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        evt["ts"], evt["source"], evt["event_type"], evt.get("src_ip"), evt.get("dst_ip"),
        evt.get("src_port"), evt.get("dst_port"), evt.get("proto"), evt.get("username"),
        evt.get("uri"), evt.get("query"), evt.get("bytes", 0), evt["raw_json"]))
    event_id = cur.lastrowid
    rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 250").fetchall()
    recent = [dict(r) for r in rows]
    for alert in detect(evt, recent):
        conn.execute("""INSERT INTO alerts (event_id,rule_id,title,severity,risk,mitre_id,mitre_name,description,created_at)
            VALUES (?,?,?,?,?,?,?,?,?)""", (
            event_id, alert["rule_id"], alert["title"], alert["severity"], alert["risk"],
            alert["mitre_id"], alert["mitre_name"], alert["description"], datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    return event_id


@app.get("/")
def root():
    return FileResponse(UI)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/demo/load")
def demo_load():
    path = Path(__file__).resolve().parent.parent / "data" / "sample_logs" / "demo.jsonl"
    if not path.exists():
        raise HTTPException(404, "Demo telemetry not found")
    count = 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        evt = normalize_zeek(raw) if raw.get("_source") == "zeek" else normalize_suricata(raw)
        insert_event(evt)
        count += 1
    return {"loaded": count}


@app.post("/api/ingest/zeek")
def ingest_zeek(body: EventIn):
    return {"event_id": insert_event(normalize_zeek(body.data))}


@app.post("/api/ingest/suricata")
def ingest_suricata(body: EventIn):
    return {"event_id": insert_event(normalize_suricata(body.data))}


@app.get("/api/events")
def events(limit: int = 100):
    conn = connect()
    rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (min(limit, 500),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/alerts")
def alerts(limit: int = 100):
    conn = connect()
    rows = conn.execute("SELECT * FROM alerts ORDER BY risk DESC, id DESC LIMIT ?", (min(limit, 500),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/incidents")
def incidents():
    conn = connect()
    rows = conn.execute("""SELECT a.*, e.src_ip, e.dst_ip, e.dst_port, e.event_type
        FROM alerts a JOIN events e ON e.id=a.event_id ORDER BY a.risk DESC, a.id DESC""").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/incidents/{incident_id}/status")
def update_status(incident_id: int, body: StatusIn):
    allowed = {"new", "investigating", "contained", "resolved", "false_positive"}
    if body.status not in allowed:
        raise HTTPException(400, "Invalid status")
    conn = connect()
    conn.execute("UPDATE alerts SET status=? WHERE id=?", (body.status, incident_id))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/metrics")
def metrics():
    conn = connect()
    result = {
        "events": conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"],
        "alerts": conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"],
        "critical": conn.execute("SELECT COUNT(*) c FROM alerts WHERE severity='critical'").fetchone()["c"],
        "high": conn.execute("SELECT COUNT(*) c FROM alerts WHERE severity='high'").fetchone()["c"],
        "medium": conn.execute("SELECT COUNT(*) c FROM alerts WHERE severity='medium'").fetchone()["c"],
    }
    conn.close()
    return result
