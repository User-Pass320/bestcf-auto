$ErrorActionPreference = "Stop"

$taskName = "BestCF Auto Update"
Start-ScheduledTask -TaskName $taskName
Write-Host "Started scheduled task: $taskName"
