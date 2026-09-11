import json
from datetime import datetime, timezone


def _ts(raw):
    value = raw.get("ts") or raw.get("timestamp")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    return str(value) if value else datetime.now(timezone.utc).isoformat()


def normalize_zeek(raw: dict) -> dict:
    return {"ts": _ts(raw), "source": "zeek", "event_type": raw.get("event_type", "conn"), "src_ip": raw.get("id.orig_h"), "dst_ip": raw.get("id.resp_h"), "src_port": raw.get("id.orig_p"), "dst_port": raw.get("id.resp_p"), "proto": raw.get("proto"), "username": raw.get("user"), "uri": raw.get("uri"), "query": raw.get("query"), "bytes": int(raw.get("orig_bytes") or 0), "raw_json": json.dumps(raw)}


def normalize_suricata(raw: dict) -> dict:
    return {"ts": _ts(raw), "source": "suricata", "event_type": raw.get("event_type", "alert"), "src_ip": raw.get("src_ip"), "dst_ip": raw.get("dest_ip"), "src_port": raw.get("src_port"), "dst_port": raw.get("dest_port"), "proto": raw.get("proto"), "username": None, "uri": raw.get("http", {}).get("url") if raw.get("http") else None, "query": raw.get("dns", {}).get("rrname") if raw.get("dns") else None, "bytes": int(raw.get("flow", {}).get("bytes_toserver", 0) or 0), "raw_json": json.dumps(raw)}
