# Register a Windows Task Scheduler job that runs wg-dns-sync every 15 minutes.
# Run this in an elevated PowerShell session.

$exe = "C:\Program Files\wg-dns-sync\wg-dns-sync.exe"
$config = "C:\ProgramData\wg-dns-sync\config.yaml"

$action = New-ScheduledTaskAction -Execute $exe `
    -Argument "update --config `"$config`""

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 15)

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask -TaskName "wg-dns-sync" `
    -Action $action -Trigger $trigger -Principal $principal `
    -Description "Update WireGuard AllowedIPs from DNS"
