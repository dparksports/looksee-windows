# Generates the identity edge-case test trace (valid JSONL, no hand-escaped
# backslashes: ConvertTo-Json does the escaping from literal PS strings).
$events = @(
    [pscustomobject]@{ type='baseline'; t='2026-10-14T10:00:00.0000000+08:00'; pid=100; services='WpnService'; ppid=700; parent='services.exe'; cmd='"C:\Windows\system32\svchost.exe" -k netsvcs -p -s WpnService' }
    [pscustomobject]@{ type='baseline'; t='2026-10-14T10:00:01.0000000+08:00'; pid=101; services='CDPUserSvc_56ec2'; ppid=700; parent='services.exe'; cmd='svchost.exe -k UnistackSvcGroup -s CDPUserSvc' }
    [pscustomobject]@{ type='baseline'; t='2026-10-14T10:00:02.0000000+08:00'; pid=102; services='wuauserv'; ppid=700; parent='services.exe'; cmd='svchost.exe -k netsvcs -s' }
    [pscustomobject]@{ type='baseline'; t='2026-10-14T10:00:03.0000000+08:00'; pid=103; services='DoSvc'; ppid=700; parent='services.exe'; cmd='svchost.exe -k netsvcs -p -s WpnService' }
    [pscustomobject]@{ type='baseline'; t='2026-10-14T10:00:04.0000000+08:00'; pid=104; services='Themes'; ppid=700; parent='services.exe'; cmd='svchost.exe -p' }
    [pscustomobject]@{ type='baseline'; t='2026-10-14T10:00:05.0000000+08:00'; pid=105; services='BITS'; ppid=700; parent='services.exe'; cmd='' }
)
$out = $events | ForEach-Object { $_ | ConvertTo-Json -Compress }
Set-Content -Path ($args[0]) -Value $out -Encoding utf8
