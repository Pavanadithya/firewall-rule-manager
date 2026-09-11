from dataclasses import dataclass

@dataclass
class Event:
    ts: str
    source: str
    event_type: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    proto: str | None = None
    username: str | None = None
    uri: str | None = None
    query: str | None = None
    bytes: int = 0
    raw_json: str = "{}"
