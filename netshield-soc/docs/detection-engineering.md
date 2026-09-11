# Detection Engineering Playbook

For each rule, define the data source, attack hypothesis, required fields, threshold, severity, ATT&CK mapping, false-positive cases, and tuning strategy.

## SSH brute force
- Data: Zeek SSH/connection telemetry
- Hypothesis: repeated attempts from one source against SSH indicate password guessing
- Threshold: 5 recent attempts
- Severity: high
- ATT&CK: T1110.001
- Tuning: allow-list approved scanners; incorporate successful logins; track source reputation; add time-window decay.

## Port scan
- Data: Zeek connection telemetry
- Hypothesis: one source contacting many destination ports indicates reconnaissance
- Threshold: 8 distinct ports
- ATT&CK: T1046
- Tuning: account for vulnerability scanners and management hosts.

## DNS tunneling
- Data: Zeek DNS telemetry
- Hypothesis: repeated long query names may indicate covert transfer
- Threshold: 5 requests with a long query
- ATT&CK: T1071.004
- Tuning: use entropy, NXDOMAIN rate, domain age, and baseline per host.

## Web attack
- Data: HTTP/Suricata telemetry
- Hypothesis: common injection/path traversal strings indicate exploitation attempts
- Severity: critical
- ATT&CK: T1190
- Tuning: decode URLs and correlate with application response codes.
