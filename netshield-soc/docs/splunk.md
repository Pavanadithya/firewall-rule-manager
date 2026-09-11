# Splunk SPL Translation Examples

## SSH brute force
```spl
index=security dest_port=22 action=failure
| bin _time span=5m
| stats count as attempts by src_ip, dest_ip, _time
| where attempts >= 5
```

## Port scan
```spl
index=network
| bin _time span=5m
| stats dc(dest_port) as distinct_ports by src_ip, dest_ip, _time
| where distinct_ports >= 8
```

## Web attack
```spl
index=web
| search uri="*union select*" OR uri="*../*" OR uri="*/etc/passwd*" OR uri="*<script*"
| table _time src_ip dest_ip uri status
```
