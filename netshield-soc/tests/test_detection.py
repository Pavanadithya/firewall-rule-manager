from app.detection_engine import detect

def test_web_attack():
    e={"event_type":"http","uri":"/x?u=union select password","src_ip":"1.1.1.1","dst_ip":"2.2.2.2"}
    alerts=detect(e,[e])
    assert any(a["rule_id"]=="NS-WEB-001" for a in alerts)

def test_port_scan():
    events=[{"event_type":"conn","src_ip":"1.1.1.1","dst_ip":"2.2.2.2","dst_port":p} for p in range(10,20)]
    alerts=detect(events[-1],events)
    assert any(a["rule_id"]=="NS-NET-001" for a in alerts)
