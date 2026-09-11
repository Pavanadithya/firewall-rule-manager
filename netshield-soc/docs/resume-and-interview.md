# Resume + Interview Guide

## Resume entry

**NetShield SOC — Enterprise Network Detection & Response Lab** | Python, FastAPI, Zeek, Suricata, MITRE ATT&CK, Docker, SQL, YAML

- Built an end-to-end SOC monitoring platform that ingested and normalized Zeek/Suricata-style telemetry, stored security events in SQL, and exposed REST APIs for investigation and incident management.
- Engineered detections for SSH brute force, network service scanning, DNS tunneling indicators, and web-attack patterns; mapped alerts to MITRE ATT&CK and prioritized incidents with risk-based severity scoring.
- Developed repeatable attack simulations, detection unit tests, analyst workflow documentation, and a browser dashboard for alert triage and incident status tracking.

## Interview story

**Problem:** Analysts need network telemetry converted into prioritized, actionable incidents rather than raw logs.

**Approach:** Normalize telemetry into a common schema, run deterministic detection logic, enrich matches with ATT&CK context, score risk, persist the incident, and provide an investigation workflow.

**Trade-off:** The local version intentionally uses SQLite and synthetic events so it is portable and safe. A production build would use a scalable event store/SIEM and real Zeek/Suricata streams.

## Questions to prepare

1. Why normalize Zeek and Suricata into a common event model?
2. How would you tune SSH brute-force detection to reduce false positives?
3. What makes DNS tunneling difficult to detect reliably?
4. Why is T1046 appropriate for port scanning?
5. How would you correlate multiple low-severity events into one incident?
6. How would you isolate a compromised workstation in an enterprise?
7. How would you ship the detections to Microsoft Sentinel or Splunk?
8. What metrics measure detection quality?

## What not to claim

Do not represent this project as two years of professional employment. Present it as a substantial personal cybersecurity/network-security lab and describe only the technologies and outcomes you actually built.
