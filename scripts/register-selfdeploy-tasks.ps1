[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$ExpectedInterfaceIndex = 19
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$projectRoot = Split-Path -Parent $repo
$wrapper = Join-Path $projectRoot 'update-bestcf-and-deploy.ps1'
if (-not (Test-Path -LiteralPath $wrapper)) {
    throw "Missing SelfDeploy wrapper: $wrapper"
}

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

$definitions = @(
    @{ Name = 'BestCF SelfDeploy Wednesday'; Day = 'Wednesday'; Time = '03:00'; Mode = 'Wednesday' },
    @{ Name = 'BestCF SelfDeploy Sunday'; Day = 'Sunday'; Time = '03:00'; Mode = 'Sunday' }
)
foreach ($definition in $definitions) {
    $arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$wrapper`" -RunMode $($definition.Mode) -ExpectedInterfaceIndex $ExpectedInterfaceIndex"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $definition.Day -At $definition.Time
    Register-ScheduledTask `
        -TaskName $definition.Name `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force | Out-Null
    Write-Host "Registered: $($definition.Name) ($($definition.Day) $($definition.Time))"
}

$legacyTask = Get-ScheduledTask -TaskName 'BestCF Auto SelfDeploy Update' -ErrorAction SilentlyContinue
if ($legacyTask) {
    Disable-ScheduledTask -TaskName $legacyTask.TaskName | Out-Null
    Write-Host "Disabled legacy task: $($legacyTask.TaskName)"
}

$preservedTask = Get-ScheduledTask -TaskName 'BestCF Auto Update' -ErrorAction SilentlyContinue
if (-not $preservedTask) {
    throw 'Preserved task is missing: BestCF Auto Update'
}
$preservedAction = ($preservedTask.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
if ($preservedAction -notlike '*C:\Users\sundewang\bestcf-auto*') {
    throw "BestCF Auto Update points to an unexpected project: $preservedAction"
}
Write-Host 'Preserved unchanged: BestCF Auto Update (Sunday 04:00)'
