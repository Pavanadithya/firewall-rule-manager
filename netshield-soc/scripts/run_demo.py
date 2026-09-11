import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import insert_event
from app.parsers import normalize_zeek, normalize_suricata

BASE = Path(__file__).resolve().parents[1] / "data" / "sample_logs"
for name in sorted(BASE.glob("*.jsonl")):
    for line in name.read_text().splitlines():
        if not line.strip():
            continue
        raw=json.loads(line)
        insert_event(normalize_zeek(raw) if raw.get("_source") == "zeek" else normalize_suricata(raw))
print("Demo telemetry loaded. Start the API with: uvicorn app.main:app --reload")
