# SentinelX - ATTACK-002
# Controlled Windows Command Shell telemetry validation
# Purpose: Generate a benign Sysmon Event ID 1

Write-Host "========================================"
Write-Host " SentinelX Command Shell Validation Test"
Write-Host "========================================"
Write-Host ""

Write-Host "[+] Starting controlled CMD test..."

cmd.exe /c whoami

Write-Host ""
Write-Host "[+] Test completed."
Write-Host "[+] Check Sysmon Event ID 1 and Wazuh Threat Hunting."