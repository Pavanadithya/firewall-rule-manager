from pathlib import Path
import csv
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.db import connect

out = Path(__file__).resolve().parents[1] / "incident_report.csv"
conn = connect()
rows = conn.execute("SELECT a.id,a.title,a.severity,a.risk,a.mitre_id,a.mitre_name,a.status,a.created_at,e.src_ip,e.dst_ip,e.dst_port FROM alerts a JOIN events e ON e.id=a.event_id ORDER BY a.risk DESC,a.id DESC").fetchall()
with out.open("w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(rows[0].keys() if rows else ["id","title","severity","risk","mitre_id","mitre_name","status","created_at","src_ip","dst_ip","dst_port"])
    writer.writerows([list(r) for r in rows])
conn.close()
print(out)
