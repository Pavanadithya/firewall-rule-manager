from pathlib import Path
import yaml

RULE_DIR = Path(__file__).resolve().parent.parent / "detections"


def load_rules():
    return [yaml.safe_load(p.read_text()) for p in RULE_DIR.glob("*.yml")]


def base_risk(severity: str) -> int:
    return {"low": 25, "medium": 50, "high": 75, "critical": 95}.get(severity, 20)


def detect(event: dict, recent_events: list[dict]):
    alerts = []
    for rule in load_rules():
        typ = rule["type"]
        matched = False
        if typ == "ssh_bruteforce":
            failures = [e for e in recent_events if e.get("src_ip") == event.get("src_ip") and e.get("dst_port") == 22 and e.get("event_type") in {"ssh", "conn"} and e.get("username") is not None]
            matched = event.get("dst_port") == 22 and len(failures) >= rule["threshold"]
        elif typ == "port_scan":
            ports = {e.get("dst_port") for e in recent_events if e.get("src_ip") == event.get("src_ip") and e.get("dst_ip") == event.get("dst_ip")}
            matched = len([p for p in ports if p]) >= rule["threshold"]
        elif typ == "dns_tunneling":
            q = event.get("query") or ""
            matched = event.get("event_type") == "dns" and len(q) >= rule["min_query_length"] and len([e for e in recent_events if e.get("src_ip") == event.get("src_ip") and e.get("event_type") == "dns"]) >= rule["threshold"]
        elif typ == "web_attack":
            uri = (event.get("uri") or "").lower()
            matched = event.get("event_type") in {"http", "alert"} and any(sig in uri for sig in rule["signatures"])
        if matched:
            alerts.append({"rule_id": rule["id"], "title": rule["title"], "severity": rule["severity"], "risk": base_risk(rule["severity"]), "mitre_id": rule["mitre_id"], "mitre_name": rule["mitre_name"], "description": rule["description"]})
    return alerts
