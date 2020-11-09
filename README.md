# CertChecks
PowerShell script to check certificate expiry dates and to create event log and email alerts.
## Test-CertificateExpiryDate.ps1
This script can test multiple hosts and multiple ports, it can email alerts and create Windows event log entries for SIEM integration. It should be run under 'SYSTEM' as a scheduled task after initial testing at a PowerShell prompt. It supports tab completion using parameters.  
e.g.
Test-CertificateExpiryDate.ps1 -Name "outlook.office365.com" -ExpiryThreshold 72 -AlertToAddress "support@mydomain.com" -port 443, 993
