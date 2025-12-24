# Module-CISA.ps1
# CISA Cybersecurity Best Practices Compliance Module
# Based on CISA alerts, advisories, and cybersecurity best practices

param(
    [Parameter(Mandatory=$true)]
    [object]$SharedData
)

$moduleName = "CISA"
$results = @()

# Helper function to add results
function Add-Result {
    param($Category, $Status, $Message, $Details = "", $Remediation = "")
    $script:results += [PSCustomObject]@{
        Module = $moduleName
        Category = $Category
        Status = $Status
        Message = $Message
        Details = $Details
        Remediation = $Remediation
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

Write-Host "`n[CISA] Starting CISA cybersecurity best practices checks..." -ForegroundColor Cyan

# ============================================================================
# CISA: Patch Management and Vulnerability Management
# ============================================================================
Write-Host "[CISA] Checking Patch Management..." -ForegroundColor Yellow

# Check Windows Update service
try {
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    if ($wuService) {
        if ($wuService.Status -eq "Running" -or $wuService.StartType -eq "Manual") {
            Add-Result -Category "CISA - Patch Management" -Status "Pass" `
                -Message "Windows Update service is available" `
                -Details "CISA Best Practice: Enable automatic updates"
        } else {
            Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                -Message "Windows Update service is disabled" `
                -Details "CISA Best Practice: Enable Windows Update for security patches" `
                -Remediation "Set-Service -Name wuauserv -StartupType Manual; Start-Service wuauserv"
        }
    }
} catch {
    Add-Result -Category "CISA - Patch Management" -Status "Error" `
        -Message "Failed to check Windows Update service: $_"
}

# Check for missing critical updates
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
    if ($updateSession) {
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        
        $criticalUpdates = $searchResult.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" }
        $importantUpdates = $searchResult.Updates | Where-Object { $_.MsrcSeverity -eq "Important" }
        
        if ($criticalUpdates.Count -eq 0 -and $importantUpdates.Count -eq 0) {
            Add-Result -Category "CISA - Patch Management" -Status "Pass" `
                -Message "All security updates are installed" `
                -Details "CISA Best Practice: Keep systems fully patched"
        } else {
            if ($criticalUpdates.Count -gt 0) {
                Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                    -Message "$($criticalUpdates.Count) critical security updates are missing" `
                    -Details "CISA Alert: Install critical patches immediately to reduce attack surface" `
                    -Remediation "Install updates via Windows Update or WSUS immediately"
            }
            if ($importantUpdates.Count -gt 0) {
                Add-Result -Category "CISA - Patch Management" -Status "Warning" `
                    -Message "$($importantUpdates.Count) important security updates are missing" `
                    -Details "CISA Best Practice: Install important updates promptly"
            }
        }
    } else {
        Add-Result -Category "CISA - Patch Management" -Status "Info" `
            -Message "Could not check for missing updates" `
            -Details "CISA Best Practice: Verify patch status regularly"
    }
} catch {
    Add-Result -Category "CISA - Patch Management" -Status "Info" `
        -Message "Update check unavailable" `
        -Details "CISA Best Practice: Implement vulnerability management program"
}

# Check Windows version support status
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $buildNumber = [System.Environment]::OSVersion.Version.Build
    
    # List of unsupported builds (this should be updated periodically)
    $unsupportedBuilds = @(10240, 10586, 14393, 15063, 16299, 17134, 17763, 18362, 18363)
    
    if ($unsupportedBuilds -contains $buildNumber) {
        Add-Result -Category "CISA - Patch Management" -Status "Fail" `
            -Message "Windows version is out of support (Build: $buildNumber)" `
            -Details "CISA Alert: Using unsupported software exposes systems to known vulnerabilities" `
            -Remediation "Upgrade to a supported Windows version immediately"
    } else {
        Add-Result -Category "CISA - Patch Management" -Status "Pass" `
            -Message "Windows version is currently supported (Build: $buildNumber)" `
            -Details "CISA Best Practice: Use supported operating systems"
    }
} catch {
    Add-Result -Category "CISA - Patch Management" -Status "Error" `
        -Message "Failed to check Windows version: $_"
}

# ============================================================================
# CISA: Multi-Factor Authentication (MFA)
# ============================================================================
Write-Host "[CISA] Checking Multi-Factor Authentication..." -ForegroundColor Yellow

# Check for Windows Hello for Business
try {
    $whfb = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -ErrorAction SilentlyContinue
    if ($whfb) {
        Add-Result -Category "CISA - MFA" -Status "Info" `
            -Message "Windows Hello for Business policies are configured" `
            -Details "CISA Best Practice: Implement MFA for all users"
    } else {
        Add-Result -Category "CISA - MFA" -Status "Info" `
            -Message "Windows Hello for Business policies not detected" `
            -Details "CISA Best Practice: Implement phishing-resistant MFA (Windows Hello, FIDO2)"
    }
} catch {
    Add-Result -Category "CISA - MFA" -Status "Info" `
        -Message "Could not check Windows Hello configuration" `
        -Details "CISA Best Practice: Deploy MFA across the organization"
}

# Check smart card policy
try {
    $smartCardPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "scforceoption" -ErrorAction SilentlyContinue
    if ($smartCardPolicy -and $smartCardPolicy.scforceoption -eq 1) {
        Add-Result -Category "CISA - MFA" -Status "Pass" `
            -Message "Smart card authentication is enforced for interactive logon" `
            -Details "CISA Best Practice: Strong authentication reduces credential theft risk"
    } else {
        Add-Result -Category "CISA - MFA" -Status "Info" `
            -Message "Smart card enforcement not configured" `
            -Details "CISA Recommendation: Implement phishing-resistant MFA"
    }
} catch {
    Add-Result -Category "CISA - MFA" -Status "Info" `
        -Message "Smart card policy check completed" `
        -Details "CISA Best Practice: Use strong authentication methods"
}

# ============================================================================
# CISA: Phishing-Resistant MFA and Credential Protection
# ============================================================================
Write-Host "[CISA] Checking Credential Protection..." -ForegroundColor Yellow

# Check Credential Guard
try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($deviceGuard -and ($deviceGuard.SecurityServicesRunning -contains 1)) {
        Add-Result -Category "CISA - Credential Protection" -Status "Pass" `
            -Message "Credential Guard is running" `
            -Details "CISA Best Practice: Credential Guard protects against credential theft attacks"
    } else {
        Add-Result -Category "CISA - Credential Protection" -Status "Warning" `
            -Message "Credential Guard is not running" `
            -Details "CISA Recommendation: Enable Credential Guard on compatible hardware" `
            -Remediation "Enable via Group Policy: Device Guard > Turn On Virtualization Based Security"
    }
} catch {
    Add-Result -Category "CISA - Credential Protection" -Status "Info" `
        -Message "Could not check Credential Guard status" `
        -Details "CISA Best Practice: Implement credential protection mechanisms"
}

# Check for WDigest (plaintext credential storage)
try {
    $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    if ($wdigest -and $wdigest.UseLogonCredential -eq 0) {
        Add-Result -Category "CISA - Credential Protection" -Status "Pass" `
            -Message "WDigest credential caching is disabled" `
            -Details "CISA Best Practice: Prevent plaintext credential storage"
    } elseif ($wdigest -and $wdigest.UseLogonCredential -eq 1) {
        Add-Result -Category "CISA - Credential Protection" -Status "Fail" `
            -Message "WDigest credential caching is enabled" `
            -Details "CISA Alert: WDigest stores plaintext credentials in memory" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
    } else {
        Add-Result -Category "CISA - Credential Protection" -Status "Pass" `
            -Message "WDigest is disabled by default (Windows 8.1+)" `
            -Details "CISA Best Practice: Credential protection is in place"
    }
} catch {
    Add-Result -Category "CISA - Credential Protection" -Status "Error" `
        -Message "Failed to check WDigest status: $_"
}

# ============================================================================
# CISA: Known Exploited Vulnerabilities (KEV)
# ============================================================================
Write-Host "[CISA] Checking for Known Exploited Vulnerabilities..." -ForegroundColor Yellow

# Check for PrintNightmare mitigation
try {
    $printNightmare = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -ErrorAction SilentlyContinue
    if ($printNightmare -and $printNightmare.RestrictDriverInstallationToAdministrators -eq 1) {
        Add-Result -Category "CISA - KEV Mitigation" -Status "Pass" `
            -Message "PrintNightmare mitigation is in place" `
            -Details "CISA KEV: CVE-2021-34527 mitigation configured"
    } else {
        Add-Result -Category "CISA - KEV Mitigation" -Status "Warning" `
            -Message "PrintNightmare mitigation not configured" `
            -Details "CISA KEV: Configure Point and Print restrictions" `
            -Remediation "Set registry key: RestrictDriverInstallationToAdministrators = 1"
    }
} catch {
    Add-Result -Category "CISA - KEV Mitigation" -Status "Info" `
        -Message "Could not verify PrintNightmare mitigation" `
        -Details "CISA KEV: Verify print spooler security settings"
}

# Check Print Spooler service status
try {
    $spooler = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
    if ($spooler -and $spooler.Status -eq "Running") {
        Add-Result -Category "CISA - KEV Mitigation" -Status "Info" `
            -Message "Print Spooler service is running" `
            -Details "CISA Guidance: Disable Print Spooler if not needed (reduces attack surface)"
    } elseif ($spooler -and $spooler.Status -eq "Stopped") {
        Add-Result -Category "CISA - KEV Mitigation" -Status "Pass" `
            -Message "Print Spooler service is stopped" `
            -Details "CISA Best Practice: Disable unnecessary services"
    }
} catch {
    Add-Result -Category "CISA - KEV Mitigation" -Status "Error" `
        -Message "Failed to check Print Spooler status: $_"
}

# ============================================================================
# CISA: Ransomware Protection
# ============================================================================
Write-Host "[CISA] Checking Ransomware Protection..." -ForegroundColor Yellow

# Check Controlled Folder Access (ransomware protection)
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus) {
        if ($defenderStatus.EnableControlledFolderAccess -eq 1) {
            Add-Result -Category "CISA - Ransomware Protection" -Status "Pass" `
                -Message "Controlled Folder Access is enabled (Block mode)" `
                -Details "CISA Best Practice: Controlled Folder Access protects against ransomware"
        } elseif ($defenderStatus.EnableControlledFolderAccess -eq 2) {
            Add-Result -Category "CISA - Ransomware Protection" -Status "Info" `
                -Message "Controlled Folder Access is in Audit mode" `
                -Details "CISA Recommendation: Enable Block mode for active protection"
        } else {
            Add-Result -Category "CISA - Ransomware Protection" -Status "Warning" `
                -Message "Controlled Folder Access is disabled" `
                -Details "CISA Best Practice: Enable Controlled Folder Access" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled"
        }
    }
} catch {
    Add-Result -Category "CISA - Ransomware Protection" -Status "Error" `
        -Message "Failed to check Controlled Folder Access: $_"
}

# Check for backups (shadow copies)
try {
    $shadowStorage = vssadmin list shadowstorage 2>$null
    if ($shadowStorage -match "Maximum Shadow Copy Storage space") {
        Add-Result -Category "CISA - Ransomware Protection" -Status "Pass" `
            -Message "Volume Shadow Copy service is configured" `
            -Details "CISA Best Practice: Maintain offline backups for ransomware recovery"
    } else {
        Add-Result -Category "CISA - Ransomware Protection" -Status "Info" `
            -Message "Could not verify shadow copy configuration" `
            -Details "CISA Best Practice: Implement regular backups"
    }
} catch {
    Add-Result -Category "CISA - Ransomware Protection" -Status "Info" `
        -Message "Shadow copy check completed" `
        -Details "CISA Best Practice: Maintain immutable backups"
}

# ============================================================================
# CISA: Logging and Detection
# ============================================================================
Write-Host "[CISA] Checking Logging and Detection..." -ForegroundColor Yellow

# Check audit policy
$criticalAudits = @(
    @{Category="Logon/Logoff"; Required="Success and Failure"}
    @{Category="Account Management"; Required="Success and Failure"}
    @{Category="Object Access"; Required="Failure"}
    @{Category="Policy Change"; Required="Success"}
    @{Category="Privilege Use"; Required="Success and Failure"}
    @{Category="Process Creation"; Required="Success"}
)

foreach ($audit in $criticalAudits) {
    try {
        $auditSetting = auditpol /get /category:"$($audit.Category)" 2>$null
        if ($auditSetting) {
            $hasSuccess = $auditSetting -match "Success"
            $hasFailure = $auditSetting -match "Failure"
            
            $meetsRequirement = $false
            if ($audit.Required -eq "Success and Failure") {
                $meetsRequirement = $hasSuccess -and $hasFailure
            } elseif ($audit.Required -eq "Success") {
                $meetsRequirement = $hasSuccess
            } elseif ($audit.Required -eq "Failure") {
                $meetsRequirement = $hasFailure
            }
            
            if ($meetsRequirement) {
                Add-Result -Category "CISA - Logging" -Status "Pass" `
                    -Message "Audit policy configured for: $($audit.Category)" `
                    -Details "CISA Best Practice: Comprehensive logging enables threat detection"
            } else {
                Add-Result -Category "CISA - Logging" -Status "Fail" `
                    -Message "Insufficient audit policy for: $($audit.Category)" `
                    -Details "CISA Requirement: Enable $($audit.Required) auditing" `
                    -Remediation "Configure via Group Policy: Advanced Audit Policy"
            }
        }
    } catch {
        # Continue with other checks
    }
}

# Check PowerShell logging (for detecting malicious scripts)
try {
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "PowerShell Script Block Logging is enabled" `
            -Details "CISA Best Practice: PowerShell logging detects malicious activity"
    } else {
        Add-Result -Category "CISA - Logging" -Status "Warning" `
            -Message "PowerShell Script Block Logging is not enabled" `
            -Details "CISA Recommendation: Enable PowerShell logging for threat detection" `
            -Remediation "Enable via Group Policy: Windows PowerShell > Turn on PowerShell Script Block Logging"
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check PowerShell logging: $_"
}

# Check event log size
try {
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    if ($securityLog) {
        $logSizeMB = [math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)
        
        if ($logSizeMB -ge 100) {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Security event log size is ${logSizeMB}MB" `
                -Details "CISA Best Practice: Adequate log retention for investigation"
        } else {
            Add-Result -Category "CISA - Logging" -Status "Warning" `
                -Message "Security event log size is ${logSizeMB}MB (may be insufficient)" `
                -Details "CISA Recommendation: Increase log size or forward to SIEM" `
                -Remediation "Increase log size and/or implement centralized logging"
        }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check event log configuration: $_"
}

# ============================================================================
# CISA: Network Security and Segmentation
# ============================================================================
Write-Host "[CISA] Checking Network Security..." -ForegroundColor Yellow

# Check Windows Firewall
try {
    $profiles = @("Domain", "Private", "Public")
    $allEnabled = $true
    
    foreach ($profile in $profiles) {
        $fwProfile = Get-NetFirewallProfile -Name $profile
        
        if ($fwProfile.Enabled) {
            if ($fwProfile.DefaultInboundAction -eq "Block") {
                Add-Result -Category "CISA - Network Security" -Status "Pass" `
                    -Message "$profile firewall: Enabled with default deny" `
                    -Details "CISA Best Practice: Host-based firewalls reduce lateral movement"
            } else {
                Add-Result -Category "CISA - Network Security" -Status "Warning" `
                    -Message "$profile firewall allows inbound by default" `
                    -Details "CISA Best Practice: Implement default deny" `
                    -Remediation "Set-NetFirewallProfile -Name $profile -DefaultInboundAction Block"
            }
        } else {
            $allEnabled = $false
            Add-Result -Category "CISA - Network Security" -Status "Fail" `
                -Message "$profile firewall is disabled" `
                -Details "CISA Alert: Enable host-based firewalls" `
                -Remediation "Set-NetFirewallProfile -Name $profile -Enabled True"
        }
    }
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Error" `
        -Message "Failed to check firewall configuration: $_"
}

# Check for SMBv1 (major ransomware vector)
try {
    $smbv1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol
    if ($smbv1 -and $smbv1.EnableSMB1Protocol -eq $false) {
        Add-Result -Category "CISA - Network Security" -Status "Pass" `
            -Message "SMBv1 protocol is disabled" `
            -Details "CISA Alert: SMBv1 was exploited by WannaCry, NotPetya"
    } elseif ($smbv1 -and $smbv1.EnableSMB1Protocol -eq $true) {
        Add-Result -Category "CISA - Network Security" -Status "Fail" `
            -Message "SMBv1 protocol is enabled" `
            -Details "CISA CRITICAL: Disable SMBv1 immediately (used by major ransomware)" `
            -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
    }
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Error" `
        -Message "Failed to check SMBv1 status: $_"
}

# Check LLMNR/NBT-NS (credential theft vectors)
try {
    $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    if ($llmnr -and $llmnr.EnableMulticast -eq 0) {
        Add-Result -Category "CISA - Network Security" -Status "Pass" `
            -Message "LLMNR is disabled" `
            -Details "CISA Best Practice: Disable LLMNR to prevent credential theft"
    } else {
        Add-Result -Category "CISA - Network Security" -Status "Warning" `
            -Message "LLMNR may be enabled" `
            -Details "CISA Recommendation: Disable LLMNR and NetBIOS" `
            -Remediation "Disable via Group Policy: DNS Client > Turn off multicast name resolution"
    }
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Info" `
        -Message "Could not verify LLMNR status" `
        -Details "CISA Best Practice: Disable legacy name resolution protocols"
}

# ============================================================================
# CISA: Endpoint Detection and Response (EDR)
# ============================================================================
Write-Host "[CISA] Checking Endpoint Protection..." -ForegroundColor Yellow

try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus) {
        # Real-time protection
        if ($defenderStatus.RealTimeProtectionEnabled) {
            Add-Result -Category "CISA - Endpoint Protection" -Status "Pass" `
                -Message "Real-time antivirus protection is enabled" `
                -Details "CISA Best Practice: Deploy and maintain endpoint protection"
        } else {
            Add-Result -Category "CISA - Endpoint Protection" -Status "Fail" `
                -Message "Real-time antivirus protection is disabled" `
                -Details "CISA CRITICAL: Enable endpoint protection" `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring $false"
        }
        
        # Cloud-delivered protection (enhanced detection)
        if ($defenderStatus.CloudProtectionEnabled -and $defenderStatus.MAPSReporting -ne 0) {
            Add-Result -Category "CISA - Endpoint Protection" -Status "Pass" `
                -Message "Cloud-delivered protection is enabled" `
                -Details "CISA Best Practice: Cloud protection provides rapid threat intelligence"
        } else {
            Add-Result -Category "CISA - Endpoint Protection" -Status "Warning" `
                -Message "Cloud-delivered protection is not fully enabled" `
                -Details "CISA Recommendation: Enable cloud protection for advanced threats" `
                -Remediation "Set-MpPreference -MAPSReporting Advanced"
        }
        
        # Tamper Protection
        if ($defenderStatus.IsTamperProtected) {
            Add-Result -Category "CISA - Endpoint Protection" -Status "Pass" `
                -Message "Tamper Protection is enabled" `
                -Details "CISA Best Practice: Prevent malware from disabling security"
        } else {
            Add-Result -Category "CISA - Endpoint Protection" -Status "Warning" `
                -Message "Tamper Protection is not enabled" `
                -Details "CISA Recommendation: Enable Tamper Protection" `
                -Remediation "Enable via Windows Security app or Intune"
        }
        
        # Signature age
        $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
        if ($signatureAge.TotalHours -le 24) {
            Add-Result -Category "CISA - Endpoint Protection" -Status "Pass" `
                -Message "Antivirus signatures updated in last 24 hours" `
                -Details "CISA Best Practice: Keep signatures current"
        } elseif ($signatureAge.Days -le 7) {
            Add-Result -Category "CISA - Endpoint Protection" -Status "Warning" `
                -Message "Antivirus signatures are $([math]::Round($signatureAge.TotalDays, 1)) days old" `
                -Details "CISA Recommendation: Update signatures daily" `
                -Remediation "Update-MpSignature"
        } else {
            Add-Result -Category "CISA - Endpoint Protection" -Status "Fail" `
                -Message "Antivirus signatures are severely outdated ($([math]::Round($signatureAge.TotalDays)) days)" `
                -Details "CISA CRITICAL: Update signatures immediately" `
                -Remediation "Update-MpSignature"
        }
    }
} catch {
    Add-Result -Category "CISA - Endpoint Protection" -Status "Error" `
        -Message "Failed to check Windows Defender status: $_"
}

# ============================================================================
# CISA: Secure Configuration
# ============================================================================
Write-Host "[CISA] Checking Secure Configuration..." -ForegroundColor Yellow

# Check for default accounts
try {
    $adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    if ($adminAccount -and $adminAccount.Enabled) {
        Add-Result -Category "CISA - Secure Configuration" -Status "Fail" `
            -Message "Built-in Administrator account is enabled" `
            -Details "CISA Best Practice: Disable or rename default accounts" `
            -Remediation "Disable-LocalUser -SID $($adminAccount.SID)"
    } else {
        Add-Result -Category "CISA - Secure Configuration" -Status "Pass" `
            -Message "Built-in Administrator account is disabled" `
            -Details "CISA Best Practice: Default accounts are secured"
    }
    
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guestAccount -and $guestAccount.Enabled) {
        Add-Result -Category "CISA - Secure Configuration" -Status "Fail" `
            -Message "Guest account is enabled" `
            -Details "CISA Best Practice: Disable guest access" `
            -Remediation "Disable-LocalUser -Name Guest"
    }
} catch {
    Add-Result -Category "CISA - Secure Configuration" -Status "Error" `
        -Message "Failed to check default accounts: $_"
}

# Check UAC
try {
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uac -and $uac.EnableLUA -eq 1) {
        Add-Result -Category "CISA - Secure Configuration" -Status "Pass" `
            -Message "User Account Control (UAC) is enabled" `
            -Details "CISA Best Practice: UAC prevents unauthorized elevation"
    } else {
        Add-Result -Category "CISA - Secure Configuration" -Status "Fail" `
            -Message "User Account Control (UAC) is disabled" `
            -Details "CISA CRITICAL: Enable UAC" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
    }
} catch {
    Add-Result -Category "CISA - Secure Configuration" -Status "Error" `
        -Message "Failed to check UAC: $_"
}

# ============================================================================
# Summary Statistics
# ============================================================================
$passCount = ($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "Fail" }).Count
$warningCount = ($results | Where-Object { $_.Status -eq "Warning" }).Count
$infoCount = ($results | Where-Object { $_.Status -eq "Info" }).Count
$errorCount = ($results | Where-Object { $_.Status -eq "Error" }).Count
$totalChecks = $results.Count

Write-Host "`n[CISA] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta

Write-Host "`nCISA Cybersecurity Performance Goals (CPGs) focus on:" -ForegroundColor Cyan
Write-Host "- Patch critical vulnerabilities within 15 days" -ForegroundColor White
Write-Host "- Implement MFA for all users" -ForegroundColor White
Write-Host "- Enable comprehensive logging and monitoring" -ForegroundColor White

return $results
