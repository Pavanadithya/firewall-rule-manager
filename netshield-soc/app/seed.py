from pathlib import Path
import json
from .main import insert_event
from .parsers import normalize_zeek, normalize_suricata

BASE = Path(__file__).resolve().parent.parent / "data" / "sample_logs"

def load_sample_data() -> int:
    count = 0
    for name in sorted(BASE.glob("*.jsonl")):
        for line in name.read_text().splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            evt = normalize_zeek(raw) if raw.get("_source") == "zeek" else normalize_suricata(raw)
            insert_event(evt)
            count += 1
    return count

if __name__ == "__main__":
    print(f"Loaded {load_sample_data()} events")
