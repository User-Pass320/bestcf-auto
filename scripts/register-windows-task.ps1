$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $projectRoot "scripts\update-local-and-push.ps1"
$launcherPath = Join-Path $projectRoot "scripts\run-update-hidden.vbs"
$taskName = "BestCF Auto Update"

if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "Missing updater script: $scriptPath"
}
if (-not (Test-Path -LiteralPath $launcherPath)) {
    throw "Missing hidden launcher script: $launcherPath"
}

$action = New-ScheduledTaskAction `
    -Execute "wscript.exe" `
    -Argument "`"$launcherPath`""

$triggerWeekly = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "04:00"

$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Limited

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew
$settings.Hidden = $true

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $triggerWeekly `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null

Write-Host "Registered scheduled task: $taskName"
Write-Host "Schedule: weekly on Sunday at 04:00"
Write-Host "Window: hidden via wscript launcher"
Write-Host "Script: $scriptPath"
