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

$triggerMorning = New-ScheduledTaskTrigger -Daily -At "08:00"
$triggerEvening = New-ScheduledTaskTrigger -Daily -At "18:00"

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
    -Trigger @($triggerMorning, $triggerEvening) `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null

Write-Host "Registered scheduled task: $taskName"
Write-Host "Schedule: daily at 08:00 and 18:00"
Write-Host "Window: hidden via wscript launcher"
Write-Host "Script: $scriptPath"
