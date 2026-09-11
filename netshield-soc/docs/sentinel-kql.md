# Microsoft Sentinel / KQL Translation Examples

These examples show how the same detection hypotheses could be implemented in Microsoft Sentinel. Connector field names vary, so treat them as portfolio examples rather than drop-in production rules.

## SSH brute force
```kusto
SigninLogs
| where ResultType != 0
| summarize Attempts=count(), Targets=dcount(IPAddress) by IPAddress, bin(TimeGenerated, 5m)
| where Attempts >= 5
| order by Attempts desc
```

## Network service scanning
```kusto
CommonSecurityLog
| summarize DistinctPorts=dcount(DestinationPort) by SourceIP, DestinationIP, bin(TimeGenerated, 5m)
| where DistinctPorts >= 8
```

## Web attack indicators
```kusto
CommonSecurityLog
| where RequestURL has_any ("union select", "../", "/etc/passwd", "<script")
| project TimeGenerated, SourceIP, DestinationIP, RequestURL, DeviceAction
```

## DNS tunneling indicators
```kusto
DnsEvents
| extend QueryLength=strlen(Name)
| summarize Requests=count(), AvgLength=avg(QueryLength), MaxLength=max(QueryLength) by ClientIP, bin(TimeGenerated, 5m)
| where Requests >= 5 and MaxLength >= 45
```
