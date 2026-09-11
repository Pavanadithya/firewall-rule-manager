# Architecture Notes

## Enterprise zones

- User VLAN: 10.10.20.0/24
- Server VLAN: 10.10.10.0/24
- Security tooling: 10.10.50.0/24
- Guest/Untrusted VLAN: 10.10.40.0/24

Telemetry models east-west and north-south traffic so an analyst can reason about reconnaissance, lateral movement, and public-facing application attacks.

## Production evolution

Replace the local event store with OpenSearch, Elasticsearch, Splunk, or Microsoft Sentinel; replace synthetic telemetry with real Zeek/Suricata EVE JSON; and connect response actions to EDR, firewall, IAM, and ticketing APIs.
