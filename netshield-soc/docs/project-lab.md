# Hands-on SOC Lab

## Scenario

A simulated enterprise has user, server, security-tooling, and guest/untrusted network zones. The analyst receives network telemetry and must identify reconnaissance, credential attacks, covert DNS activity, and web exploitation attempts.

## Analyst workflow

1. Run the synthetic telemetry generator.
2. Start the API/dashboard.
3. Review the incident queue by risk.
4. Pivot from alert to source/destination and event details.
5. Map the behavior to ATT&CK.
6. Record containment and tuning recommendations.
7. Export the incident report.

## Evidence to discuss in an interview

- Why each rule fires
- What data fields are required
- False-positive scenarios
- Threshold and time-window tradeoffs
- How you would add allowlists and asset criticality
- How you would forward events to Sentinel/Splunk
- How an EDR/firewall integration would perform containment
