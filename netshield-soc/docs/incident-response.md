# Incident Response Workflow

1. **Triage:** confirm the alert and identify source, destination, protocol, and timing.
2. **Scope:** search related events by source IP, destination IP, username, URI, and time window.
3. **Contain:** block the source at the firewall/EDR, disable compromised credentials when appropriate, and isolate affected hosts.
4. **Eradicate:** remove persistence, patch the exploited service, rotate credentials, and close the control gap.
5. **Recover:** restore service, verify telemetry, and monitor for recurrence.
6. **Lessons learned:** document root cause, control weakness, detection quality, and next tuning action.

## Analyst evidence checklist

- Alert/rule ID and ATT&CK technique
- Source/destination and affected asset
- First seen / last seen timestamps
- Related authentication, DNS, HTTP, and connection events
- Containment action and approval
- Recovery validation
- Detection tuning recommendation
