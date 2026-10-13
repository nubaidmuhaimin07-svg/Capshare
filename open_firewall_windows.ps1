# Optional: let OTHER devices on your own network reach CapShare.
#
# Adds ONE Windows Firewall rule:
#   inbound TCP 8765-8775, only from your local subnet (LocalSubnet), only on networks
#   Windows has labelled "Private". It is never opened to the internet.
#
# Needs administrator rights:  right-click -> "Run with PowerShell" and accept the prompt,
# or open PowerShell as administrator and run this file.
# To remove the rule later:   Remove-NetFirewallRule -DisplayName "CapShare (local network)"

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Restarting as administrator (accept the Windows prompt) ..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    exit
}

$name = "CapShare (local network)"
if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
    Write-Host "The rule already exists." -ForegroundColor Green
} else {
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP `
        -LocalPort 8765-8775 -Profile Private -RemoteAddress LocalSubnet | Out-Null
    Write-Host "Rule added: TCP 8765-8775 from the local subnet, Private networks only." -ForegroundColor Green
}
Write-Host ""
Write-Host "If a device still cannot connect, make sure your Wi-Fi is set to 'Private network':"
Write-Host "  Settings > Network & internet > Wi-Fi > (your network) > Network profile type > Private"
Read-Host "Press Enter to close"
