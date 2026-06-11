$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$secretPath = Join-Path $projectRoot "template.b64.txt"

if (-not (Test-Path -LiteralPath $secretPath)) {
    throw "Missing template.b64.txt. Regenerate it from template.yaml before setting the GitHub secret."
}

$secret = Get-Content -LiteralPath $secretPath -Raw
if ([string]::IsNullOrWhiteSpace($secret)) {
    throw "template.b64.txt is empty."
}

Set-Clipboard -Value $secret
Write-Host "TEMPLATE_YAML_B64 copied to clipboard. Length: $($secret.Length)"
