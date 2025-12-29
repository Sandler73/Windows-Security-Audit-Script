# Module-MS.ps1
# Microsoft Security Baseline Compliance Module
# Version: 5.0
# Based on Microsoft Security Compliance Toolkit and Security Baselines

<#
.SYNOPSIS
    Microsoft Security Baseline compliance checks.

.DESCRIPTION
    This module checks alignment with Microsoft Security Baselines including:
    - Windows Security Baseline settings
    - Microsoft Edge security configuration
    - Microsoft Office security settings (if applicable)
    - Windows Defender Application Control
    - Exploit Protection settings
    - Attack Surface Reduction rules
    - Controlled Folder Access
    - Network Protection
    - Microsoft Defender SmartScreen
    - Windows Hello for Business
    - Credential protection mechanisms
    - Device Guard and Code Integrity

.PARAMETER SharedData
    Hashtable containing shared data from the main script

.NOTES
    Version: 5.0
    Based on: Microsoft Security Compliance Toolkit (SCT) and Security Baselines
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "MS"
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

Write-Host "`n[MS] Starting Microsoft Security Baseline checks..." -ForegroundColor Cyan

# ============================================================================
# MS Baseline: Windows Defender Antivirus
# ============================================================================
Write-Host "[MS] Checking Windows Defender Antivirus Configuration..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction Stop
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    
    # Real-time protection
    if ($mpStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Real-time protection is enabled" `
            -Details "MS Baseline: Real-time scanning provides continuous protection"
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "Real-time protection is DISABLED" `
            -Details "MS Baseline: Enable real-time protection immediately" `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }
    
    # Behavior monitoring
    if ($mpStatus.BehaviorMonitorEnabled) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Behavior monitoring is enabled" `
            -Details "MS Baseline: Detects malicious behavior patterns"
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "Behavior monitoring is disabled" `
            -Details "MS Baseline: Enable behavior monitoring" `
            -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false"
    }
    
    # IOAV (IE/Outlook/Attachments) protection
    if ($mpStatus.IoavProtectionEnabled) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "IOAV protection (downloaded files and attachments) is enabled" `
            -Details "MS Baseline: Scans downloads and email attachments"
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "IOAV protection is disabled" `
            -Details "MS Baseline: Enable IOAV protection" `
            -Remediation "Set-MpPreference -DisableIOAVProtection `$false"
    }
    
    # On-access protection
    if ($mpStatus.OnAccessProtectionEnabled) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "On-access protection is enabled" `
            -Details "MS Baseline: Files are scanned when accessed"
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "On-access protection is disabled" `
            -Details "MS Baseline: Enable on-access scanning" `
            -Remediation "Set-MpPreference -DisableOnAccessProtection `$false"
    }
    
    # Cloud-delivered protection (MAPS)
    if ($mpStatus.MAPSReporting -gt 0) {
        $mapsLevel = switch ($mpStatus.MAPSReporting) {
            1 { "Basic" }
            2 { "Advanced" }
            default { "Unknown" }
        }
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Cloud-delivered protection is enabled (Level: $mapsLevel)" `
            -Details "MS Baseline: Cloud protection provides rapid threat response"
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "Cloud-delivered protection is disabled" `
            -Details "MS Baseline: Enable MAPS reporting" `
            -Remediation "Set-MpPreference -MAPSReporting Advanced"
    }
    
    # Automatic sample submission
    if ($mpPreference.SubmitSamplesConsent -eq 1 -or $mpPreference.SubmitSamplesConsent -eq 3) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Automatic sample submission is enabled" `
            -Details "MS Baseline: Helps Microsoft identify new threats"
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Warning" `
            -Message "Automatic sample submission is not fully enabled" `
            -Details "MS Baseline: Consider enabling automatic sample submission" `
            -Remediation "Set-MpPreference -SubmitSamplesConsent SendSafeSamples"
    }
    
    # PUA (Potentially Unwanted Applications) protection
    if ($mpPreference.PUAProtection -eq 1) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "PUA (Potentially Unwanted Applications) protection is enabled" `
            -Details "MS Baseline: Blocks potentially unwanted software"
    } elseif ($mpPreference.PUAProtection -eq 2) {
        Add-Result -Category "MS - Defender AV" -Status "Info" `
            -Message "PUA protection is in audit mode" `
            -Details "MS Baseline: Consider enabling block mode"
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Warning" `
            -Message "PUA protection is disabled" `
            -Details "MS Baseline: Enable PUA protection" `
            -Remediation "Set-MpPreference -PUAProtection Enabled"
    }
    
    # Check signature update age
    $signatureAge = (Get-Date) - $mpStatus.AntivirusSignatureLastUpdated
    if ($signatureAge.Days -eq 0) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Antivirus signatures were updated today" `
            -Details "MS Baseline: Signatures are current"
    } elseif ($signatureAge.Days -le 3) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Antivirus signatures are $($signatureAge.Days) day(s) old" `
            -Details "MS Baseline: Signatures are reasonably current"
    } elseif ($signatureAge.Days -le 7) {
        Add-Result -Category "MS - Defender AV" -Status "Warning" `
            -Message "Antivirus signatures are $($signatureAge.Days) days old" `
            -Details "MS Baseline: Update signatures more frequently" `
            -Remediation "Update-MpSignature"
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "Antivirus signatures are severely outdated ($($signatureAge.Days) days old)" `
            -Details "MS Baseline: Critical - update immediately" `
            -Remediation "Update-MpSignature"
    }
    
    # Scan frequency
    if ($mpStatus.QuickScanAge -le 7) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Quick scan performed within the last 7 days" `
            -Details "MS Baseline: Regular scanning is occurring"
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Warning" `
            -Message "Last quick scan was $($mpStatus.QuickScanAge) days ago" `
            -Details "MS Baseline: Schedule regular scans" `
            -Remediation "Start-MpScan -ScanType QuickScan"
    }
    
} catch {
    Add-Result -Category "MS - Defender AV" -Status "Error" `
        -Message "Failed to check Windows Defender Antivirus: $_"
}

# ============================================================================
# MS Baseline: Exploit Protection (EMET Replacement)
# ============================================================================
Write-Host "[MS] Checking Exploit Protection Configuration..." -ForegroundColor Yellow

try {
    # Check if Exploit Protection is configured
    $exploitProtection = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
    
    if ($exploitProtection) {
        # DEP (Data Execution Prevention)
        if ($exploitProtection.DEP.Enable -eq "ON" -or $exploitProtection.DEP.Enable -eq "NOTSET") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "Data Execution Prevention (DEP) is enabled" `
                -Details "MS Baseline: DEP prevents code execution in data-only memory pages"
        } else {
            Add-Result -Category "MS - Exploit Protection" -Status "Warning" `
                -Message "DEP may not be optimally configured" `
                -Details "MS Baseline: Ensure DEP is enabled system-wide"
        }
        
        # SEHOP (Structured Exception Handler Overwrite Protection)
        if ($exploitProtection.SEHOP.Enable -eq "ON" -or $exploitProtection.SEHOP.Enable -eq "NOTSET") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "SEHOP is enabled" `
                -Details "MS Baseline: Protects against SEH overwrites"
        }
        
        # ASLR (Address Space Layout Randomization)
        if ($exploitProtection.ASLR.ForceRelocateImages -eq "ON") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "ASLR Force Relocate Images is enabled" `
                -Details "MS Baseline: Randomizes memory addresses to prevent exploits"
        }
        
        # Control Flow Guard
        if ($exploitProtection.CFG.Enable -eq "ON") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "Control Flow Guard (CFG) is enabled" `
                -Details "MS Baseline: Protects against control flow hijacking"
        } else {
            Add-Result -Category "MS - Exploit Protection" -Status "Info" `
                -Message "Control Flow Guard is not universally enabled" `
                -Details "MS Baseline: CFG provides additional exploit mitigation"
        }
        
        Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
            -Message "Exploit Protection settings are configured" `
            -Details "MS Baseline: System-wide exploit mitigations are in place"
    } else {
        Add-Result -Category "MS - Exploit Protection" -Status "Warning" `
            -Message "Could not verify Exploit Protection configuration" `
            -Details "MS Baseline: Ensure exploit mitigations are enabled"
    }
} catch {
    Add-Result -Category "MS - Exploit Protection" -Status "Error" `
        -Message "Failed to check Exploit Protection: $_"
}

# ============================================================================
# MS Baseline: Attack Surface Reduction (ASR) Rules
# ============================================================================
Write-Host "[MS] Checking Attack Surface Reduction Rules..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction Stop
    
    $asrRuleIds = $mpPreference.AttackSurfaceReductionRules_Ids
    $asrRuleActions = $mpPreference.AttackSurfaceReductionRules_Actions
    
    if ($asrRuleIds -and $asrRuleIds.Count -gt 0) {
        $enabledCount = ($asrRuleActions | Where-Object { $_ -eq 1 }).Count
        $auditCount = ($asrRuleActions | Where-Object { $_ -eq 2 }).Count
        $disabledCount = ($asrRuleActions | Where-Object { $_ -eq 0 }).Count
        
        Add-Result -Category "MS - ASR" -Status "Pass" `
            -Message "Attack Surface Reduction rules are configured ($($asrRuleIds.Count) rules)" `
            -Details "MS Baseline: ASR reduces attack vectors. Enabled: $enabledCount, Audit: $auditCount, Disabled: $disabledCount"
        
        # Recommended ASR rules per Microsoft baseline
        $recommendedRules = @{
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
            "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
            "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
            "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files from running unless they meet prevalence, age, or trusted list criteria"
            "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from Windows local security authority subsystem (lsass.exe)"
            "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations originating from PSExec and WMI commands"
            "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted and unsigned processes that run from USB"
            "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication applications from creating child processes"
            "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
            "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
        }
        
        $configuredRecommended = 0
        foreach ($ruleId in $asrRuleIds) {
            if ($recommendedRules.ContainsKey($ruleId)) {
                $configuredRecommended++
            }
        }
        
        if ($configuredRecommended -ge 10) {
            Add-Result -Category "MS - ASR" -Status "Pass" `
                -Message "Most recommended ASR rules are configured ($configuredRecommended of $($recommendedRules.Count))" `
                -Details "MS Baseline: Comprehensive ASR rule coverage"
        } elseif ($configuredRecommended -ge 5) {
            Add-Result -Category "MS - ASR" -Status "Warning" `
                -Message "Some recommended ASR rules are configured ($configuredRecommended of $($recommendedRules.Count))" `
                -Details "MS Baseline: Consider enabling additional recommended rules"
        } else {
            Add-Result -Category "MS - ASR" -Status "Warning" `
                -Message "Few recommended ASR rules are configured ($configuredRecommended of $($recommendedRules.Count))" `
                -Details "MS Baseline: Enable recommended ASR rules for better protection"
        }
        
    } else {
        Add-Result -Category "MS - ASR" -Status "Warning" `
            -Message "No Attack Surface Reduction rules are configured" `
            -Details "MS Baseline: ASR rules provide important attack mitigations" `
            -Remediation "Configure ASR rules via Group Policy or PowerShell: Add-MpPreference -AttackSurfaceReductionRules_Ids <RuleId> -AttackSurfaceReductionRules_Actions Enabled"
    }
    
} catch {
    Add-Result -Category "MS - ASR" -Status "Error" `
        -Message "Failed to check ASR rules: $_"
}

# ============================================================================
# MS Baseline: Network Protection
# ============================================================================
Write-Host "[MS] Checking Network Protection..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction Stop
    
    $networkProtection = $mpPreference.EnableNetworkProtection
    
    switch ($networkProtection) {
        0 {
            Add-Result -Category "MS - Network Protection" -Status "Fail" `
                -Message "Network Protection is disabled" `
                -Details "MS Baseline: Enable Network Protection to block malicious network traffic" `
                -Remediation "Set-MpPreference -EnableNetworkProtection Enabled"
        }
        1 {
            Add-Result -Category "MS - Network Protection" -Status "Pass" `
                -Message "Network Protection is enabled (Block mode)" `
                -Details "MS Baseline: Blocks connections to malicious domains and IPs"
        }
        2 {
            Add-Result -Category "MS - Network Protection" -Status "Warning" `
                -Message "Network Protection is in Audit mode" `
                -Details "MS Baseline: Enable Block mode for active protection" `
                -Remediation "Set-MpPreference -EnableNetworkProtection Enabled"
        }
        default {
            Add-Result -Category "MS - Network Protection" -Status "Warning" `
                -Message "Network Protection status is unknown" `
                -Details "MS Baseline: Verify Network Protection configuration"
        }
    }
    
} catch {
    Add-Result -Category "MS - Network Protection" -Status "Error" `
        -Message "Failed to check Network Protection: $_"
}

# ============================================================================
# MS Baseline: Controlled Folder Access (Ransomware Protection)
# ============================================================================
Write-Host "[MS] Checking Controlled Folder Access..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction Stop
    
    $controlledFolderAccess = $mpPreference.EnableControlledFolderAccess
    
    switch ($controlledFolderAccess) {
        0 {
            Add-Result -Category "MS - Ransomware Protection" -Status "Warning" `
                -Message "Controlled Folder Access is disabled" `
                -Details "MS Baseline: CFA protects important folders from ransomware" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled"
        }
        1 {
            Add-Result -Category "MS - Ransomware Protection" -Status "Pass" `
                -Message "Controlled Folder Access is enabled (Block mode)" `
                -Details "MS Baseline: Protected folders are guarded against unauthorized changes"
            
            # List protected folders
            $protectedFolders = $mpPreference.ControlledFolderAccessProtectedFolders
            if ($protectedFolders) {
                Add-Result -Category "MS - Ransomware Protection" -Status "Info" `
                    -Message "Custom protected folders: $($protectedFolders.Count)" `
                    -Details "MS Baseline: Additional folders beyond defaults are protected"
            }
        }
        2 {
            Add-Result -Category "MS - Ransomware Protection" -Status "Info" `
                -Message "Controlled Folder Access is in Audit mode" `
                -Details "MS Baseline: Consider enabling Block mode after testing" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled"
        }
        default {
            Add-Result -Category "MS - Ransomware Protection" -Status "Warning" `
                -Message "Controlled Folder Access status is unknown"
        }
    }
    
} catch {
    Add-Result -Category "MS - Ransomware Protection" -Status "Error" `
        -Message "Failed to check Controlled Folder Access: $_"
}

# ============================================================================
# MS Baseline: SmartScreen Configuration
# ============================================================================
Write-Host "[MS] Checking SmartScreen Configuration..." -ForegroundColor Yellow

# Windows Defender SmartScreen for apps and files
try {
    $smartScreenEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
    
    if ($smartScreenEnabled) {
        $value = $smartScreenEnabled.SmartScreenEnabled
        
        switch ($value) {
            "Off" {
                Add-Result -Category "MS - SmartScreen" -Status "Fail" `
                    -Message "Windows SmartScreen is disabled" `
                    -Details "MS Baseline: Enable SmartScreen to protect against malicious downloads" `
                    -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -Value 'Warn'"
            }
            "Warn" {
                Add-Result -Category "MS - SmartScreen" -Status "Pass" `
                    -Message "Windows SmartScreen is enabled (Warn)" `
                    -Details "MS Baseline: Users are warned about unrecognized apps"
            }
            "RequireAdmin" {
                Add-Result -Category "MS - SmartScreen" -Status "Pass" `
                    -Message "Windows SmartScreen is enabled (Require Admin)" `
                    -Details "MS Baseline: Admin approval required for unrecognized apps"
            }
            default {
                Add-Result -Category "MS - SmartScreen" -Status "Info" `
                    -Message "Windows SmartScreen configuration: $value"
            }
        }
    }
} catch {
    Add-Result -Category "MS - SmartScreen" -Status "Error" `
        -Message "Failed to check SmartScreen: $_"
}

# SmartScreen for Microsoft Edge
try {
    $edgeSmartScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
    
    if ($edgeSmartScreen -and $edgeSmartScreen.SmartScreenEnabled -eq 1) {
        Add-Result -Category "MS - SmartScreen" -Status "Pass" `
            -Message "Microsoft Edge SmartScreen is enabled" `
            -Details "MS Baseline: Web-based threat protection is active"
    } elseif ($edgeSmartScreen -and $edgeSmartScreen.SmartScreenEnabled -eq 0) {
        Add-Result -Category "MS - SmartScreen" -Status "Warning" `
            -Message "Microsoft Edge SmartScreen is disabled" `
            -Details "MS Baseline: Enable SmartScreen in Edge" `
            -Remediation "Configure via Group Policy: Microsoft Edge > SmartScreen settings"
    } else {
        Add-Result -Category "MS - SmartScreen" -Status "Info" `
            -Message "Microsoft Edge SmartScreen policy not configured (may use default)" `
            -Details "MS Baseline: SmartScreen is enabled by default in Edge"
    }
    
    # SmartScreen for potentially unwanted apps
    $edgePUA = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -ErrorAction SilentlyContinue
    
    if ($edgePUA -and $edgePUA.SmartScreenPuaEnabled -eq 1) {
        Add-Result -Category "MS - SmartScreen" -Status "Pass" `
            -Message "Edge SmartScreen PUA blocking is enabled" `
            -Details "MS Baseline: Blocks potentially unwanted applications"
    }
    
} catch {
    # Edge may not be installed or configured via policy
}

# ============================================================================
# MS Baseline: Device Guard / WDAC (Windows Defender Application Control)
# ============================================================================
Write-Host "[MS] Checking Device Guard and Application Control..." -ForegroundColor Yellow

try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    
    if ($deviceGuard) {
        # Check if virtualization-based security is available
        $vbsStatus = $deviceGuard.VirtualizationBasedSecurityStatus
        
        switch ($vbsStatus) {
            0 {
                Add-Result -Category "MS - Device Guard" -Status "Info" `
                    -Message "Virtualization-based security (VBS) is not enabled" `
                    -Details "MS Baseline: VBS requires compatible hardware and firmware"
            }
            1 {
                Add-Result -Category "MS - Device Guard" -Status "Pass" `
                    -Message "Virtualization-based security is enabled but not running" `
                    -Details "MS Baseline: VBS is configured"
            }
            2 {
                Add-Result -Category "MS - Device Guard" -Status "Pass" `
                    -Message "Virtualization-based security is enabled and running" `
                    -Details "MS Baseline: Hardware-based security features are active"
            }
        }
        
        # Check Credential Guard
        if ($deviceGuard.SecurityServicesRunning -contains 1) {
            Add-Result -Category "MS - Device Guard" -Status "Pass" `
                -Message "Credential Guard is running" `
                -Details "MS Baseline: Credentials are protected in isolated environment"
        } else {
            Add-Result -Category "MS - Device Guard" -Status "Info" `
                -Message "Credential Guard is not running" `
                -Details "MS Baseline: Enable on compatible systems for credential protection"
        }
        
        # Check HVCI (Hypervisor-protected Code Integrity)
        if ($deviceGuard.SecurityServicesRunning -contains 2) {
            Add-Result -Category "MS - Device Guard" -Status "Pass" `
                -Message "Hypervisor-protected Code Integrity (HVCI) is running" `
                -Details "MS Baseline: Code integrity is enforced by hypervisor"
        } else {
            Add-Result -Category "MS - Device Guard" -Status "Info" `
                -Message "HVCI is not running" `
                -Details "MS Baseline: HVCI provides kernel-mode code integrity"
        }
        
        # Check Code Integrity Policy
        $ciPolicy = $deviceGuard.CodeIntegrityPolicyEnforcementStatus
        
        switch ($ciPolicy) {
            0 {
                Add-Result -Category "MS - Device Guard" -Status "Info" `
                    -Message "Code Integrity Policy is not enforced" `
                    -Details "MS Baseline: WDAC/Device Guard not configured"
            }
            1 {
                Add-Result -Category "MS - Device Guard" -Status "Pass" `
                    -Message "Code Integrity Policy is enforced" `
                    -Details "MS Baseline: Application whitelisting is active"
            }
            2 {
                Add-Result -Category "MS - Device Guard" -Status "Info" `
                    -Message "Code Integrity Policy is in audit mode" `
                    -Details "MS Baseline: WDAC is monitoring but not blocking"
            }
        }
        
        # Check Secure Boot
        if ($deviceGuard.SecureBootRequired) {
            Add-Result -Category "MS - Device Guard" -Status "Pass" `
                -Message "Secure Boot is required by Device Guard configuration" `
                -Details "MS Baseline: Boot integrity is enforced"
        }
        
    } else {
        Add-Result -Category "MS - Device Guard" -Status "Info" `
            -Message "Device Guard information not available" `
            -Details "MS Baseline: May require specific hardware/firmware support"
    }
    
} catch {
    Add-Result -Category "MS - Device Guard" -Status "Error" `
        -Message "Failed to check Device Guard: $_"
}

# ============================================================================
# MS Baseline: Credential Protection
# ============================================================================
Write-Host "[MS] Checking Credential Protection Settings..." -ForegroundColor Yellow

# Check LSASS as Protected Process
try {
    $lsassProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    
    if ($lsassProtection -and $lsassProtection.RunAsPPL -eq 1) {
        Add-Result -Category "MS - Credential Protection" -Status "Pass" `
            -Message "LSASS is running as Protected Process Light (PPL)" `
            -Details "MS Baseline: LSASS is protected from credential dumping tools"
    } else {
        Add-Result -Category "MS - Credential Protection" -Status "Warning" `
            -Message "LSASS PPL is not enabled" `
            -Details "MS Baseline: Enable PPL to protect against credential theft" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1; Restart-Computer"
    }
} catch {
    Add-Result -Category "MS - Credential Protection" -Status "Error" `
        -Message "Failed to check LSASS PPL: $_"
}

# Check WDigest credential caching
try {
    $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    
    if ($wdigest -and $wdigest.UseLogonCredential -eq 0) {
        Add-Result -Category "MS - Credential Protection" -Status "Pass" `
            -Message "WDigest plaintext credential storage is disabled" `
            -Details "MS Baseline: Prevents plaintext credentials in memory"
    } elseif ($wdigest -and $wdigest.UseLogonCredential -eq 1) {
        Add-Result -Category "MS - Credential Protection" -Status "Fail" `
            -Message "WDigest plaintext credential storage is ENABLED" `
            -Details "MS Baseline: Disable WDigest immediately" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
    } else {
        Add-Result -Category "MS - Credential Protection" -Status "Pass" `
            -Message "WDigest is disabled by default (modern Windows)" `
            -Details "MS Baseline: Secure default configuration"
    }
} catch {
    Add-Result -Category "MS - Credential Protection" -Status "Error" `
        -Message "Failed to check WDigest: $_"
}

# Check cached credentials limit
try {
    $cachedLogons = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -ErrorAction SilentlyContinue
    
    if ($cachedLogons) {
        $count = $cachedLogons.CachedLogonsCount
        
        if ($count -le 4) {
            Add-Result -Category "MS - Credential Protection" -Status "Pass" `
                -Message "Cached logon count is limited to $count" `
                -Details "MS Baseline: Reduces offline attack exposure"
        } elseif ($count -le 10) {
            Add-Result -Category "MS - Credential Protection" -Status "Warning" `
                -Message "Cached logon count is $count" `
                -Details "MS Baseline: Consider reducing to 4 or fewer" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 4"
        } else {
            Add-Result -Category "MS - Credential Protection" -Status "Fail" `
                -Message "Cached logon count is high ($count)" `
                -Details "MS Baseline: Reduce cached credentials" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 4"
        }
    }
} catch {
    Add-Result -Category "MS - Credential Protection" -Status "Error" `
        -Message "Failed to check cached logon count: $_"
}

# ============================================================================
# MS Baseline: Windows Hello for Business
# ============================================================================
Write-Host "[MS] Checking Windows Hello for Business..." -ForegroundColor Yellow

try {
    $whfbPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -ErrorAction SilentlyContinue
    
    if ($whfbPolicy) {
        $enabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -ErrorAction SilentlyContinue
        
        if ($enabled -and $enabled.Enabled -eq 1) {
            Add-Result -Category "MS - Windows Hello" -Status "Pass" `
                -Message "Windows Hello for Business is enabled via policy" `
                -Details "MS Baseline: Modern passwordless authentication is available"
            
            # Check PIN complexity
            $pinComplexity = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -ErrorAction SilentlyContinue
            
            if ($pinComplexity) {
                $minLength = $pinComplexity.MinimumPINLength
                if ($minLength -ge 6) {
                    Add-Result -Category "MS - Windows Hello" -Status "Pass" `
                        -Message "Windows Hello PIN minimum length is $minLength" `
                        -Details "MS Baseline: PIN complexity requirements are configured"
                }
            }
        } else {
            Add-Result -Category "MS - Windows Hello" -Status "Info" `
                -Message "Windows Hello for Business is not enabled via policy" `
                -Details "MS Baseline: Consider enabling for passwordless authentication"
        }
    } else {
        Add-Result -Category "MS - Windows Hello" -Status "Info" `
            -Message "Windows Hello for Business policy not configured" `
            -Details "MS Baseline: WHFB provides biometric and PIN-based authentication"
    }
    
} catch {
    Add-Result -Category "MS - Windows Hello" -Status "Error" `
        -Message "Failed to check Windows Hello configuration: $_"
}

# ============================================================================
# MS Baseline: Remote Desktop Security
# ============================================================================
Write-Host "[MS] Checking Remote Desktop Security..." -ForegroundColor Yellow

try {
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 1) {
        Add-Result -Category "MS - RDP Security" -Status "Pass" `
            -Message "Remote Desktop is disabled" `
            -Details "MS Baseline: RDP is disabled - no remote access risk"
    } else {
        # RDP is enabled, check security settings
        Add-Result -Category "MS - RDP Security" -Status "Info" `
            -Message "Remote Desktop is enabled" `
            -Details "MS Baseline: Verify RDP security settings"
        
        # Check NLA (Network Level Authentication)
        $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        
        if ($nla -and $nla.UserAuthentication -eq 1) {
            Add-Result -Category "MS - RDP Security" -Status "Pass" `
                -Message "RDP: Network Level Authentication is required" `
                -Details "MS Baseline: NLA provides additional authentication layer"
        } else {
            Add-Result -Category "MS - RDP Security" -Status "Fail" `
                -Message "RDP: Network Level Authentication is NOT required" `
                -Details "MS Baseline: Enable NLA for RDP" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        }
        
        # Check encryption level
        $encLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        
        if ($encLevel -and $encLevel.MinEncryptionLevel -ge 3) {
            Add-Result -Category "MS - RDP Security" -Status "Pass" `
                -Message "RDP: Encryption level is set to High" `
                -Details "MS Baseline: Strong encryption protects RDP sessions"
        } else {
            Add-Result -Category "MS - RDP Security" -Status "Warning" `
                -Message "RDP: Encryption level may not be set to High" `
                -Details "MS Baseline: Set encryption to High" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3"
        }
        
        # Check Security Layer
        $secLayer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue
        
        if ($secLayer -and $secLayer.SecurityLayer -eq 2) {
            Add-Result -Category "MS - RDP Security" -Status "Pass" `
                -Message "RDP: Security layer is set to SSL (TLS 1.0)" `
                -Details "MS Baseline: Encrypted RDP connections"
        }
    }
    
} catch {
    Add-Result -Category "MS - RDP Security" -Status "Error" `
        -Message "Failed to check RDP security: $_"
}

# ============================================================================
# MS Baseline: PowerShell Security
# ============================================================================
Write-Host "[MS] Checking PowerShell Security Settings..." -ForegroundColor Yellow

# Check PowerShell v2 status
try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    
    if ($psv2) {
        if ($psv2.State -eq "Disabled") {
            Add-Result -Category "MS - PowerShell Security" -Status "Pass" `
                -Message "PowerShell v2 is disabled" `
                -Details "MS Baseline: PowerShell v2 lacks security features and should be removed"
        } else {
            Add-Result -Category "MS - PowerShell Security" -Status "Fail" `
                -Message "PowerShell v2 is ENABLED" `
                -Details "MS Baseline: Remove PowerShell v2 to prevent downgrade attacks" `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"
        }
    }
} catch {
    Add-Result -Category "MS - PowerShell Security" -Status "Info" `
        -Message "Could not check PowerShell v2 status"
}

# Check PowerShell Script Block Logging
try {
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    
    if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Add-Result -Category "MS - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Script Block Logging is enabled" `
            -Details "MS Baseline: Logs PowerShell command execution for security monitoring"
    } else {
        Add-Result -Category "MS - PowerShell Security" -Status "Warning" `
            -Message "PowerShell Script Block Logging is not enabled" `
            -Details "MS Baseline: Enable for security monitoring" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1"
    }
} catch {
    Add-Result -Category "MS - PowerShell Security" -Status "Error" `
        -Message "Failed to check PowerShell Script Block Logging: $_"
}

# Check PowerShell Transcription
try {
    $transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    
    if ($transcription -and $transcription.EnableTranscripting -eq 1) {
        $outputDir = $transcription.OutputDirectory
        Add-Result -Category "MS - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Transcription is enabled" `
            -Details "MS Baseline: Full session logging to: $outputDir"
    } else {
        Add-Result -Category "MS - PowerShell Security" -Status "Info" `
            -Message "PowerShell Transcription is not enabled" `
            -Details "MS Baseline: Transcription provides complete PowerShell session logs"
    }
} catch {
    Add-Result -Category "MS - PowerShell Security" -Status "Error" `
        -Message "Failed to check PowerShell Transcription: $_"
}

# Check Constrained Language Mode
try {
    if ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {
        Add-Result -Category "MS - PowerShell Security" -Status "Pass" `
            -Message "PowerShell is running in Constrained Language Mode" `
            -Details "MS Baseline: Restricts potentially dangerous PowerShell features"
    } else {
        Add-Result -Category "MS - PowerShell Security" -Status "Info" `
            -Message "PowerShell is running in $($ExecutionContext.SessionState.LanguageMode) mode" `
            -Details "MS Baseline: Constrained Language Mode is typically enforced via AppLocker/WDAC"
    }
} catch {
    Add-Result -Category "MS - PowerShell Security" -Status "Error" `
        -Message "Failed to check PowerShell Language Mode: $_"
}

# ============================================================================
# MS Baseline: Windows Firewall
# ============================================================================
Write-Host "[MS] Checking Windows Firewall Baseline..." -ForegroundColor Yellow

$firewallProfiles = @("Domain", "Private", "Public")

foreach ($profileName in $firewallProfiles) {
    try {
        $MSprofile = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
        
        if ($MSprofile.Enabled) {
            Add-Result -Category "MS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Firewall is enabled" `
                -Details "MS Baseline: Network protection is active"
        } else {
            Add-Result -Category "MS - Firewall" -Status "Fail" `
                -Message "$profileName Profile: Firewall is DISABLED" `
                -Details "MS Baseline: Enable firewall immediately" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -Enabled True"
        }
        
        if ($MSprofile.DefaultInboundAction -eq "Block") {
            Add-Result -Category "MS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Default inbound is Block" `
                -Details "MS Baseline: Default deny reduces attack surface"
        } else {
            Add-Result -Category "MS - Firewall" -Status "Fail" `
                -Message "$profileName Profile: Default inbound is Allow" `
                -Details "MS Baseline: Set to Block" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -DefaultInboundAction Block"
        }
        
    } catch {
        Add-Result -Category "MS - Firewall" -Status "Error" `
            -Message "Failed to check $profileName firewall profile: $_"
    }
}

# ============================================================================
# MS Baseline: SMB Security
# ============================================================================
Write-Host "[MS] Checking SMB Security Baseline..." -ForegroundColor Yellow

# Check SMBv1
try {
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    
    if ($smb1Feature.State -eq "Disabled") {
        Add-Result -Category "MS - SMB Security" -Status "Pass" `
            -Message "SMBv1 protocol is disabled" `
            -Details "MS Baseline: SMBv1 has critical vulnerabilities and is disabled"
    } else {
        Add-Result -Category "MS - SMB Security" -Status "Fail" `
            -Message "SMBv1 protocol is ENABLED" `
            -Details "MS Baseline: Disable SMBv1 immediately (WannaCry, NotPetya vector)" `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
    }
} catch {
    Add-Result -Category "MS - SMB Security" -Status "Error" `
        -Message "Failed to check SMBv1 status: $_"
}

# Check SMB signing and encryption
try {
    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    
    if ($smbServer) {
        if ($smbServer.RequireSecuritySignature) {
            Add-Result -Category "MS - SMB Security" -Status "Pass" `
                -Message "SMB server signing is required" `
                -Details "MS Baseline: Prevents tampering and relay attacks"
        } else {
            Add-Result -Category "MS - SMB Security" -Status "Fail" `
                -Message "SMB server signing is not required" `
                -Details "MS Baseline: Require SMB signing" `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
        }
        
        if ($smbServer.EncryptData) {
            Add-Result -Category "MS - SMB Security" -Status "Pass" `
                -Message "SMB encryption is enabled" `
                -Details "MS Baseline: SMB traffic is encrypted"
        } else {
            Add-Result -Category "MS - SMB Security" -Status "Info" `
                -Message "SMB encryption is not globally enabled" `
                -Details "MS Baseline: Consider enabling for sensitive data"
        }
    }
} catch {
    Add-Result -Category "MS - SMB Security" -Status "Error" `
        -Message "Failed to check SMB configuration: $_"
}

# ============================================================================
# Summary Statistics
# ============================================================================
$passCount = @($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount = @($results | Where-Object { $_.Status -eq "Fail" }).Count
$warningCount = @($results | Where-Object { $_.Status -eq "Warning" }).Count
$infoCount = @($results | Where-Object { $_.Status -eq "Info" }).Count
$errorCount = @($results | Where-Object { $_.Status -eq "Error" }).Count
$totalChecks = $results.Count

Write-Host "`n[MS] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta

return $results
