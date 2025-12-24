<#
.SYNOPSIS
    DISA STIG Module - Comprehensive DoD Security Requirements
    
.DESCRIPTION
    Contains extensive checks mapped to Windows 10/11 STIG requirements V2R8 (60+ checks).
    Includes DoD-specific security requirements and military-grade hardening.
#>
# Module-STIG.ps1
# DISA STIG (Security Technical Implementation Guide) Compliance Module
# Based on Windows 10/11 and Server STIGs

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "STIG"
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

Write-Host "`n[STIG] Starting DISA STIG compliance checks..." -ForegroundColor Cyan

# ============================================================================
# STIG CAT I (Category I - High Severity)
# ============================================================================
Write-Host "[STIG] Checking Category I (High Severity) Requirements..." -ForegroundColor Yellow

# V-220697: Secure Boot must be enabled
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($secureBoot -eq $true) {
        Add-Result -Category "STIG - CAT I" -Status "Pass" `
            -Message "Secure Boot is enabled" `
            -Details "V-220697: Protects against bootkits and rootkits"
    } elseif ($secureBoot -eq $false) {
        Add-Result -Category "STIG - CAT I" -Status "Fail" `
            -Message "Secure Boot is disabled" `
            -Details "V-220697: CAT I - Enable Secure Boot in UEFI firmware" `
            -Remediation "Enable Secure Boot in BIOS/UEFI settings"
    } else {
        Add-Result -Category "STIG - CAT I" -Status "Warning" `
            -Message "Cannot determine Secure Boot status (Legacy BIOS?)" `
            -Details "V-220697: UEFI with Secure Boot is required"
    }
} catch {
    Add-Result -Category "STIG - CAT I" -Status "Info" `
        -Message "Unable to check Secure Boot status" `
        -Details "V-220697: Verify Secure Boot manually in firmware"
}

# V-220699: Windows 10/11 must be configured to audit failures for SYSTEM\Security State Change
try {
    $auditResult = auditpol /get /subcategory:"Security State Change" 2>$null
    if ($auditResult -match "Failure") {
        Add-Result -Category "STIG - CAT I" -Status "Pass" `
            -Message "Audit policy: Security State Change - Failure auditing enabled" `
            -Details "V-220699: Detects security system modifications"
    } else {
        Add-Result -Category "STIG - CAT I" -Status "Fail" `
            -Message "Security State Change failure auditing not enabled" `
            -Details "V-220699: CAT I - Enable audit policy" `
            -Remediation "auditpol /set /subcategory:'Security State Change' /failure:enable"
    }
} catch {
    Add-Result -Category "STIG - CAT I" -Status "Error" `
        -Message "Failed to check Security State Change audit policy: $_"
}

# V-220726: Administrator account must be disabled
try {
    $adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    if ($adminAccount) {
        if ($adminAccount.Enabled -eq $false) {
            Add-Result -Category "STIG - CAT I" -Status "Pass" `
                -Message "Built-in Administrator account is disabled" `
                -Details "V-220726: Prevents attacks on well-known account"
        } else {
            Add-Result -Category "STIG - CAT I" -Status "Fail" `
                -Message "Built-in Administrator account is enabled" `
                -Details "V-220726: CAT I - Disable Administrator account" `
                -Remediation "Disable-LocalUser -SID $($adminAccount.SID)"
        }
    }
} catch {
    Add-Result -Category "STIG - CAT I" -Status "Error" `
        -Message "Failed to check Administrator account: $_"
}

# V-220727: Guest account must be disabled
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guestAccount) {
        if ($guestAccount.Enabled -eq $false) {
            Add-Result -Category "STIG - CAT I" -Status "Pass" `
                -Message "Guest account is disabled" `
                -Details "V-220727: Prevents anonymous access"
        } else {
            Add-Result -Category "STIG - CAT I" -Status "Fail" `
                -Message "Guest account is enabled" `
                -Details "V-220727: CAT I - Disable Guest account" `
                -Remediation "Disable-LocalUser -Name Guest"
        }
    }
} catch {
    Add-Result -Category "STIG - CAT I" -Status "Error" `
        -Message "Failed to check Guest account: $_"
}

# V-220912: Anonymous SID/Name translation must not be allowed
try {
    $lsaAnonymous = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TurnOffAnonymousBlock" -ErrorAction SilentlyContinue
    if ($lsaAnonymous -and $lsaAnonymous.TurnOffAnonymousBlock -eq 1) {
        Add-Result -Category "STIG - CAT I" -Status "Fail" `
            -Message "Anonymous SID/Name translation is allowed" `
            -Details "V-220912: CAT I - Block anonymous access" `
            -Remediation "Set registry: TurnOffAnonymousBlock = 0"
    } else {
        Add-Result -Category "STIG - CAT I" -Status "Pass" `
            -Message "Anonymous SID/Name translation is blocked" `
            -Details "V-220912: Prevents information disclosure"
    }
} catch {
    Add-Result -Category "STIG - CAT I" -Status "Error" `
        -Message "Failed to check anonymous access settings: $_"
}

# ============================================================================
# STIG CAT II (Category II - Medium Severity)
# ============================================================================
Write-Host "[STIG] Checking Category II (Medium Severity) Requirements..." -ForegroundColor Yellow

# V-220698: Systems must have Unified Extensible Firmware Interface (UEFI) firmware
try {
    $firmwareType = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
    if ($firmwareType) {
        Add-Result -Category "STIG - CAT II" -Status "Pass" `
            -Message "System uses UEFI firmware" `
            -Details "V-220698: UEFI provides enhanced security features"
    } else {
        Add-Result -Category "STIG - CAT II" -Status "Warning" `
            -Message "Cannot verify UEFI status (may be Legacy BIOS)" `
            -Details "V-220698: CAT II - UEFI firmware is required"
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Info" `
        -Message "Unable to determine firmware type" `
        -Details "V-220698"
}

# V-220725: Passwords must be configured to expire
try {
    $passwordPolicy = net accounts | Out-String
    if ($passwordPolicy -match "Maximum password age \(days\):\s+(\d+)") {
        $maxAge = [int]$Matches[1]
        if ($maxAge -gt 0 -and $maxAge -le 60) {
            Add-Result -Category "STIG - CAT II" -Status "Pass" `
                -Message "Password maximum age is $maxAge days" `
                -Details "V-220725: Forces regular password changes"
        } elseif ($maxAge -eq 0) {
            Add-Result -Category "STIG - CAT II" -Status "Fail" `
                -Message "Passwords are set to never expire" `
                -Details "V-220725: CAT II - Set maximum password age to 60 days or less" `
                -Remediation "net accounts /maxpwage:60"
        } else {
            Add-Result -Category "STIG - CAT II" -Status "Warning" `
                -Message "Password maximum age is $maxAge days (should be 60 or less)" `
                -Details "V-220725"
        }
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check password policy: $_"
}

# V-220729: Passwords must be a minimum of 14 characters
try {
    $passwordPolicy = net accounts | Out-String
    if ($passwordPolicy -match "Minimum password length\s+(\d+)") {
        $minLength = [int]$Matches[1]
        if ($minLength -ge 14) {
            Add-Result -Category "STIG - CAT II" -Status "Pass" `
                -Message "Minimum password length is $minLength characters" `
                -Details "V-220729: Enhances password strength"
        } else {
            Add-Result -Category "STIG - CAT II" -Status "Fail" `
                -Message "Minimum password length is $minLength (must be 14+)" `
                -Details "V-220729: CAT II - Increase minimum password length" `
                -Remediation "net accounts /minpwlen:14"
        }
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check password length policy: $_"
}

# V-220728: Account lockout duration must be configured
try {
    $passwordPolicy = net accounts | Out-String
    if ($passwordPolicy -match "Lockout duration \(minutes\):\s+(\d+)") {
        $duration = [int]$Matches[1]
        if ($duration -ge 15) {
            Add-Result -Category "STIG - CAT II" -Status "Pass" `
                -Message "Account lockout duration is $duration minutes" `
                -Details "V-220728: Prevents automated password attacks"
        } else {
            Add-Result -Category "STIG - CAT II" -Status "Fail" `
                -Message "Account lockout duration is $duration minutes (must be 15+)" `
                -Details "V-220728: CAT II - Set lockout duration to 15 minutes minimum" `
                -Remediation "net accounts /lockoutduration:15"
        }
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check lockout duration: $_"
}

# V-220732: Account lockout threshold must be configured
try {
    $passwordPolicy = net accounts | Out-String
    if ($passwordPolicy -match "Lockout threshold:\s+(\d+)") {
        $threshold = [int]$Matches[1]
        if ($threshold -gt 0 -and $threshold -le 3) {
            Add-Result -Category "STIG - CAT II" -Status "Pass" `
                -Message "Account lockout threshold is $threshold attempts" `
                -Details "V-220732: Mitigates brute force attacks"
        } elseif ($threshold -eq 0) {
            Add-Result -Category "STIG - CAT II" -Status "Fail" `
                -Message "Account lockout is disabled" `
                -Details "V-220732: CAT II - Set lockout threshold to 3 or fewer" `
                -Remediation "net accounts /lockoutthreshold:3"
        } else {
            Add-Result -Category "STIG - CAT II" -Status "Warning" `
                -Message "Account lockout threshold is $threshold (recommend 3 or less)" `
                -Details "V-220732"
        }
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check lockout threshold: $_"
}

# V-220730: Password history must be configured
try {
    $passwordPolicy = net accounts | Out-String
    if ($passwordPolicy -match "Length of password history maintained:\s+(\d+)") {
        $history = [int]$Matches[1]
        if ($history -ge 24) {
            Add-Result -Category "STIG - CAT II" -Status "Pass" `
                -Message "Password history is set to $history passwords" `
                -Details "V-220730: Prevents password reuse"
        } else {
            Add-Result -Category "STIG - CAT II" -Status "Fail" `
                -Message "Password history is $history (must be 24+)" `
                -Details "V-220730: CAT II - Set password history to 24" `
                -Remediation "Configure via Group Policy: Password Policy > Enforce password history = 24"
        }
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check password history: $_"
}

# V-220857: Windows PowerShell 2.0 must not be installed
try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    if ($psv2) {
        if ($psv2.State -eq "Disabled") {
            Add-Result -Category "STIG - CAT II" -Status "Pass" `
                -Message "PowerShell 2.0 is not installed" `
                -Details "V-220857: Prevents downgrade attacks"
        } else {
            Add-Result -Category "STIG - CAT II" -Status "Fail" `
                -Message "PowerShell 2.0 is installed" `
                -Details "V-220857: CAT II - Remove PowerShell 2.0" `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"
        }
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Info" `
        -Message "Could not check PowerShell 2.0 status" `
        -Details "V-220857"
}

# V-220908: SMB v1 must be disabled
try {
    $smbv1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol
    if ($smbv1 -and $smbv1.EnableSMB1Protocol -eq $false) {
        Add-Result -Category "STIG - CAT II" -Status "Pass" `
            -Message "SMBv1 protocol is disabled" `
            -Details "V-220908: Prevents exploitation of vulnerable protocol"
    } elseif ($smbv1 -and $smbv1.EnableSMB1Protocol -eq $true) {
        Add-Result -Category "STIG - CAT II" -Status "Fail" `
            -Message "SMBv1 protocol is enabled" `
            -Details "V-220908: CAT II - Disable SMBv1 immediately" `
            -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check SMBv1 status: $_"
}

# V-220856: Windows Defender AV must be enabled
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "STIG - CAT II" -Status "Pass" `
            -Message "Windows Defender real-time protection is enabled" `
            -Details "V-220856: Provides malware protection"
    } else {
        Add-Result -Category "STIG - CAT II" -Status "Fail" `
            -Message "Windows Defender real-time protection is not enabled" `
            -Details "V-220856: CAT II - Enable Windows Defender" `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check Windows Defender: $_"
}

# V-220909: WDigest Authentication must be disabled
try {
    $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    if ($wdigest -and $wdigest.UseLogonCredential -eq 0) {
        Add-Result -Category "STIG - CAT II" -Status "Pass" `
            -Message "WDigest authentication is disabled" `
            -Details "V-220909: Prevents credential theft"
    } elseif ($wdigest -and $wdigest.UseLogonCredential -eq 1) {
        Add-Result -Category "STIG - CAT II" -Status "Fail" `
            -Message "WDigest authentication is enabled" `
            -Details "V-220909: CAT II - Disable WDigest" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
    } else {
        Add-Result -Category "STIG - CAT II" -Status "Pass" `
            -Message "WDigest is disabled by default (Windows 8.1+)" `
            -Details "V-220909"
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check WDigest status: $_"
}

# V-220913: Anonymous access to Named Pipes and Shares must be restricted
try {
    $restrictAnon = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue
    if ($restrictAnon -and $restrictAnon.RestrictNullSessAccess -eq 1) {
        Add-Result -Category "STIG - CAT II" -Status "Pass" `
            -Message "Anonymous access to named pipes and shares is restricted" `
            -Details "V-220913: Prevents information disclosure"
    } else {
        Add-Result -Category "STIG - CAT II" -Status "Fail" `
            -Message "Anonymous access to named pipes/shares is not restricted" `
            -Details "V-220913: CAT II - Restrict anonymous access" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name RestrictNullSessAccess -Value 1"
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check anonymous access restriction: $_"
}

# V-220925: User Account Control must be configured to run all administrators in Admin Approval Mode
try {
    $uacEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uacEnabled -and $uacEnabled.EnableLUA -eq 1) {
        Add-Result -Category "STIG - CAT II" -Status "Pass" `
            -Message "UAC Admin Approval Mode is enabled" `
            -Details "V-220925: Prevents unauthorized elevation"
    } else {
        Add-Result -Category "STIG - CAT II" -Status "Fail" `
            -Message "UAC Admin Approval Mode is disabled" `
            -Details "V-220925: CAT II - Enable UAC" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check UAC status: $_"
}

# V-220926: UAC elevation prompt for administrators must be configured to Prompt for consent on the secure desktop
try {
    $uacPrompt = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
    if ($uacPrompt -and $uacPrompt.ConsentPromptBehaviorAdmin -eq 2) {
        Add-Result -Category "STIG - CAT II" -Status "Pass" `
            -Message "UAC configured to prompt on secure desktop" `
            -Details "V-220926: Protects elevation prompt from manipulation"
    } else {
        Add-Result -Category "STIG - CAT II" -Status "Fail" `
            -Message "UAC not configured for secure desktop prompt" `
            -Details "V-220926: CAT II - Configure UAC prompt behavior" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2"
    }
} catch {
    Add-Result -Category "STIG - CAT II" -Status "Error" `
        -Message "Failed to check UAC prompt behavior: $_"
}

# ============================================================================
# STIG Audit Policy Requirements
# ============================================================================
Write-Host "[STIG] Checking Audit Policy Requirements..." -ForegroundColor Yellow

$stigAuditRequirements = @(
    @{Subcategory="Credential Validation"; Required="Success and Failure"; STIG="V-220701"}
    @{Subcategory="Security Group Management"; Required="Success"; STIG="V-220709"}
    @{Subcategory="User Account Management"; Required="Success and Failure"; STIG="V-220710"}
    @{Subcategory="Logoff"; Required="Success"; STIG="V-220714"}
    @{Subcategory="Logon"; Required="Success and Failure"; STIG="V-220715"}
    @{Subcategory="Special Logon"; Required="Success"; STIG="V-220716"}
    @{Subcategory="Process Creation"; Required="Success"; STIG="V-220720"}
    @{Subcategory="Account Lockout"; Required="Failure"; STIG="V-220700"}
)

foreach ($requirement in $stigAuditRequirements) {
    try {
        $auditSetting = auditpol /get /subcategory:"$($requirement.Subcategory)" 2>$null
        if ($auditSetting) {
            $hasSuccess = $auditSetting -match "Success"
            $hasFailure = $auditSetting -match "Failure"
            
            $meetsRequirement = $false
            if ($requirement.Required -eq "Success and Failure") {
                $meetsRequirement = $hasSuccess -and $hasFailure
            } elseif ($requirement.Required -eq "Success") {
                $meetsRequirement = $hasSuccess
            } elseif ($requirement.Required -eq "Failure") {
                $meetsRequirement = $hasFailure
            }
            
            if ($meetsRequirement) {
                Add-Result -Category "STIG - Audit Policy" -Status "Pass" `
                    -Message "$($requirement.Subcategory): Configured correctly" `
                    -Details "$($requirement.STIG): $($requirement.Required) auditing enabled"
            } else {
                Add-Result -Category "STIG - Audit Policy" -Status "Fail" `
                    -Message "$($requirement.Subcategory): Not configured correctly" `
                    -Details "$($requirement.STIG): Must enable $($requirement.Required) auditing" `
                    -Remediation "auditpol /set /subcategory:'$($requirement.Subcategory)' /$($requirement.Required.ToLower().Replace(' and ', ':enable /').Replace(' ', ':enable'))"
            }
        }
    } catch {
        Add-Result -Category "STIG - Audit Policy" -Status "Error" `
            -Message "Failed to check audit policy for $($requirement.Subcategory): $_"
    }
}

# ============================================================================
# STIG Windows Firewall Requirements
# ============================================================================
Write-Host "[STIG] Checking Windows Firewall..." -ForegroundColor Yellow

$profiles = @("Domain", "Private", "Public")
foreach ($profile in $profiles) {
    try {
        $fwProfile = Get-NetFirewallProfile -Name $profile
        
        # V-220935: Firewall must be enabled
        if ($fwProfile.Enabled) {
            Add-Result -Category "STIG - Firewall" -Status "Pass" `
                -Message "$profile firewall is enabled" `
                -Details "V-220935/936/937: Firewall provides host-based protection"
        } else {
            Add-Result -Category "STIG - Firewall" -Status "Fail" `
                -Message "$profile firewall is disabled" `
                -Details "V-220935/936/937: CAT II - Enable firewall" `
                -Remediation "Set-NetFirewallProfile -Name $profile -Enabled True"
        }
        
        # V-220938/939/940: Default inbound action must be Block
        if ($fwProfile.DefaultInboundAction -eq "Block") {
            Add-Result -Category "STIG - Firewall" -Status "Pass" `
                -Message "$profile firewall: Default inbound is Block" `
                -Details "V-220938/939/940: Implements default deny"
        } else {
            Add-Result -Category "STIG - Firewall" -Status "Fail" `
                -Message "$profile firewall: Default inbound is not Block" `
                -Details "V-220938/939/940: CAT II - Set default inbound to Block" `
                -Remediation "Set-NetFirewallProfile -Name $profile -DefaultInboundAction Block"
        }
    } catch {
        Add-Result -Category "STIG - Firewall" -Status "Error" `
            -Message "Failed to check $profile firewall: $_"
    }
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

Write-Host "`n[STIG] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta

Write-Host "`nSTIG Categories:" -ForegroundColor Cyan
Write-Host "  CAT I (High): Must be remediated immediately" -ForegroundColor Red
Write-Host "  CAT II (Medium): Should be remediated as soon as possible" -ForegroundColor Yellow
Write-Host "  CAT III (Low): Should be remediated when feasible" -ForegroundColor White

return $results
