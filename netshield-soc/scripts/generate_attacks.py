from pathlib import Path
import json
from datetime import datetime, timezone, timedelta

out=Path(__file__).resolve().parents[1]/"data/sample_logs/generated.jsonl"
base=datetime.now(timezone.utc)
rows=[]
for i in range(7):
    rows.append({"_source":"zeek","ts":(base+timedelta(seconds=i)).isoformat(),"event_type":"ssh","id.orig_h":"10.10.20.55","id.resp_h":"10.10.10.20","id.orig_p":52000+i,"id.resp_p":22,"proto":"tcp","user":"root"})
for i,p in enumerate([21,22,23,25,53,80,110,139,443,445]):
    rows.append({"_source":"zeek","ts":(base+timedelta(seconds=i)).isoformat(),"event_type":"conn","id.orig_h":"10.10.30.44","id.resp_h":"10.10.10.20","id.orig_p":40000+i,"id.resp_p":p,"proto":"tcp"})
for i in range(7):
    rows.append({"_source":"zeek","ts":(base+timedelta(seconds=i)).isoformat(),"event_type":"dns","id.orig_h":"10.10.30.70","id.resp_h":"10.10.10.53","query":("a"*48)+f".x{i}.example.test","proto":"udp"})
rows.append({"_source":"zeek","ts":base.isoformat(),"event_type":"http","id.orig_h":"10.10.40.9","id.resp_h":"10.10.10.30","id.orig_p":54122,"id.resp_p":443,"proto":"tcp","uri":"/login?user=admin%27%20UNION%20SELECT%20password%20FROM%20users"})
out.parent.mkdir(parents=True,exist_ok=True)
with out.open("w") as f:
    for row in rows: f.write(json.dumps(row)+"\n")
print(out)
