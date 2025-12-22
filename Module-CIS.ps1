<#
.SYNOPSIS
    CIS Benchmark Module - CIS Windows 10/11 Enterprise v2.0.0
    
.DESCRIPTION
    Contains checks specific to CIS Benchmark recommendations beyond core checks.
    Includes audit policies, user rights assignments, security options, and advanced settings.
#>

function Invoke-CISChecks {
    param([string]$Severity = 'ALL')
    
    $results = @{Passed=@(); Failed=@(); Warnings=@(); Info=@()}
    
    function Add-Check {
        param($Category,$Status,$Message,$Details="",$Current="N/A",$Expected="N/A",$Sev="Medium",$Remediation="",$CISControl="")
        
        if($Severity -ne 'ALL' -and $Severity -ne $Sev){return}
        
        $result = [PSCustomObject]@{
            Category=$Category; Status=$Status; Message=$Message; Details=$Details
            CurrentValue=$Current; ExpectedValue=$Expected; Severity=$Sev
            Remediation=$Remediation; Frameworks="CIS $CISControl"
        }
        
        $results.$Status += $result
    }
    
    Write-Host "Running CIS Benchmark Checks..." -ForegroundColor Cyan
    
    # Get audit policy details
    $auditCategories = @{}
    auditpol /get /category:* | ForEach-Object {
        if($_ -match '^\s+(.+?)\s{2,}(Success and Failure|Success|Failure|No Auditing)$'){
            $auditCategories[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    
    # CIS 17.1 - Account Logon
    @(
        @{Name='Credential Validation'; CIS='17.1.1'; Expected='Success and Failure'}
        @{Name='Kerberos Authentication Service'; CIS='17.1.2'; Expected='Success and Failure'}
    ) | ForEach-Object {
        $current = $auditCategories[$_.Name]
        if($current -eq $_.Expected){
            Add-Check -Category "Audit Policy" -Status "Passed" -Message "$($_.Name) audit OK" `
                -Current $current -Expected $_.Expected -Sev "Medium" -CISControl $_.CIS
        } else {
            Add-Check -Category "Audit Policy" -Status "Failed" -Message "$($_.Name) audit not configured" `
                -Current $current -Expected $_.Expected -Sev "Medium" `
                -Remediation "auditpol /set /subcategory:`"$($_.Name)`" /success:enable /failure:enable" `
                -CISControl $_.CIS
        }
    }
    
    # CIS 17.2 - Account Management
    @(
        @{Name='Security Group Management'; CIS='17.2.1'; Expected='Success'; Sev='Medium'}
        @{Name='User Account Management'; CIS='17.2.2'; Expected='Success and Failure'; Sev='Medium'}
    ) | ForEach-Object {
        $current = $auditCategories[$_.Name]
        if($current -eq $_.Expected){
            Add-Check -Category "Audit Policy" -Status "Passed" -Message "$($_.Name) audit OK" `
                -Current $current -Expected $_.Expected -Sev $_.Sev -CISControl $_.CIS
        } else {
            $cmd = if($_.Expected -eq 'Success'){"auditpol /set /subcategory:`"$($_.Name)`" /success:enable /failure:disable"}
                  else{"auditpol /set /subcategory:`"$($_.Name)`" /success:enable /failure:enable"}
            Add-Check -Category "Audit Policy" -Status "Failed" -Message "$($_.Name) audit not configured" `
                -Current $current -Expected $_.Expected -Sev $_.Sev `
                -Remediation $cmd -CISControl $_.CIS
        }
    }
    
    # CIS 17.5 - Logon/Logoff
    @(
        @{Name='Logon'; CIS='17.5.1'; Expected='Success and Failure'; Sev='Medium'}
        @{Name='Logoff'; CIS='17.5.2'; Expected='Success'; Sev='Low'}
        @{Name='Account Lockout'; CIS='17.5.3'; Expected='Failure'; Sev='Medium'}
        @{Name='Special Logon'; CIS='17.5.4'; Expected='Success'; Sev='Medium'}
    ) | ForEach-Object {
        $current = $auditCategories[$_.Name]
        if($current -eq $_.Expected){
            Add-Check -Category "Audit Policy" -Status "Passed" -Message "$($_.Name) audit OK" `
                -Current $current -Expected $_.Expected -Sev $_.Sev -CISControl $_.CIS
        } else {
            $cmd = switch($_.Expected){
                'Success'{"auditpol /set /subcategory:`"$($_.Name)`" /success:enable /failure:disable"}
                'Failure'{"auditpol /set /subcategory:`"$($_.Name)`" /success:disable /failure:enable"}
                default{"auditpol /set /subcategory:`"$($_.Name)`" /success:enable /failure:enable"}
            }
            Add-Check -Category "Audit Policy" -Status "Failed" -Message "$($_.Name) audit not configured" `
                -Current $current -Expected $_.Expected -Sev $_.Sev `
                -Remediation $cmd -CISControl $_.CIS
        }
    }
    
    # CIS 17.7 - Policy Change
    @(
        @{Name='Audit Policy Change'; CIS='17.7.1'; Expected='Success'; Sev='Medium'}
        @{Name='Authentication Policy Change'; CIS='17.7.2'; Expected='Success'; Sev='Medium'}
    ) | ForEach-Object {
        $current = $auditCategories[$_.Name]
        if($current -eq $_.Expected -or $current -eq 'Success and Failure'){
            Add-Check -Category "Audit Policy" -Status "Passed" -Message "$($_.Name) audit OK" `
                -Current $current -Expected $_.Expected -Sev $_.Sev -CISControl $_.CIS
        } else {
            Add-Check -Category "Audit Policy" -Status "Failed" -Message "$($_.Name) audit not configured" `
                -Current $current -Expected $_.Expected -Sev $_.Sev `
                -Remediation "auditpol /set /subcategory:`"$($_.Name)`" /success:enable /failure:disable" `
                -CISControl $_.CIS
        }
    }
    
    # CIS 17.8 - Privilege Use
    $current = $auditCategories['Sensitive Privilege Use']
    if($current -eq 'Success and Failure'){
        Add-Check -Category "Audit Policy" -Status "Passed" -Message "Sensitive Privilege Use audit OK" `
            -Current $current -Expected "Success and Failure" -Sev "Medium" -CISControl "17.8.1"
    } else {
        Add-Check -Category "Audit Policy" -Status "Failed" -Message "Sensitive Privilege Use audit not configured" `
            -Current $current -Expected "Success and Failure" -Sev "Medium" `
            -Remediation "auditpol /set /subcategory:`"Sensitive Privilege Use`" /success:enable /failure:enable" `
            -CISControl "17.8.1"
    }
    
    # CIS 17.9 - System Events
    @(
        @{Name='Security State Change'; CIS='17.9.2'; Expected='Success'; Sev='Medium'}
        @{Name='Security System Extension'; CIS='17.9.3'; Expected='Success'; Sev='Medium'}
        @{Name='System Integrity'; CIS='17.9.4'; Expected='Success and Failure'; Sev='Medium'}
    ) | ForEach-Object {
        $current = $auditCategories[$_.Name]
        if($current -eq $_.Expected){
            Add-Check -Category "Audit Policy" -Status "Passed" -Message "$($_.Name) audit OK" `
                -Current $current -Expected $_.Expected -Sev $_.Sev -CISControl $_.CIS
        } else {
            $cmd = if($_.Expected -eq 'Success'){"auditpol /set /subcategory:`"$($_.Name)`" /success:enable /failure:disable"}
                  else{"auditpol /set /subcategory:`"$($_.Name)`" /success:enable /failure:enable"}
            Add-Check -Category "Audit Policy" -Status "Failed" -Message "$($_.Name) audit not configured" `
                -Current $current -Expected $_.Expected -Sev $_.Sev `
                -Remediation $cmd -CISControl $_.CIS
        }
    }
    
    # CIS 2.2.1 - Access this computer from network
    # Note: This requires secedit export which is covered in detail checks
    
    # CIS 2.3.4 - Accounts: Administrator account status
    try {
        $admin = Get-LocalUser | Where-Object{$_.SID -like "*-500"} | Select-Object -First 1
        if($admin -and -not $admin.Enabled){
            Add-Check -Category "Accounts" -Status "Passed" -Message "Built-in Administrator disabled" `
                -Current "Disabled" -Expected "Disabled" -Sev "Medium" -CISControl "2.3.1.1"
        } elseif($admin -and $admin.Enabled){
            Add-Check -Category "Accounts" -Status "Warnings" -Message "Built-in Administrator enabled" `
                -Current "Enabled" -Expected "Disabled (if not needed)" -Sev "Medium" `
                -Details "Should be disabled unless required for specific scenarios" -CISControl "2.3.1.1"
        }
    } catch {}
    
    # CIS 2.3.11 - Network access: Do not allow anonymous enumeration
    $anonEnum = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue).RestrictAnonymous
    if($anonEnum -eq 1){
        Add-Check -Category "Network Security" -Status "Passed" -Message "Anonymous enumeration restricted" `
            -Current "Restricted" -Expected "Restricted" -Sev "Medium" -CISControl "2.3.11.5"
    } else {
        Add-Check -Category "Network Security" -Status "Failed" -Message "Anonymous enumeration NOT restricted" `
            -Current "Allowed" -Expected "Restricted" -Sev "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1" `
            -CISControl "2.3.11.5"
    }
    
    # CIS 18.1 - Control Panel
    $disableCPL = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoControlPanel" -ErrorAction SilentlyContinue).NoControlPanel
    # This is typically not enforced for admin users but documented in CIS
    
    # CIS 18.3 - MSS (Microsoft Security Guide)
    $mssPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    
    $disableIPSourceRouting = (Get-ItemProperty -Path $mssPath -Name "DisableIPSourceRouting" -ErrorAction SilentlyContinue).DisableIPSourceRouting
    if($disableIPSourceRouting -eq 2){
        Add-Check -Category "Network Security" -Status "Passed" -Message "IP source routing disabled" `
            -Current "Highest protection (2)" -Expected "2" -Sev "Low" -CISControl "18.3.5"
    } else {
        Add-Check -Category "Network Security" -Status "Failed" -Message "IP source routing not optimally configured" `
            -Current $(if($disableIPSourceRouting){"$disableIPSourceRouting"}else{"Not Set"}) -Expected "2" -Sev "Low" `
            -Remediation "Set-ItemProperty -Path '$mssPath' -Name 'DisableIPSourceRouting' -Value 2" `
            -CISControl "18.3.5"
    }
    
    # CIS 18.4 - Network
    $netPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    
    # CIS 18.5 - DNS Client
    $dnsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    
    $turnOffMulticast = (Get-ItemProperty -Path $dnsPath -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    if($turnOffMulticast -eq 0){
        Add-Check -Category "DNS Client" -Status "Passed" -Message "Multicast name resolution disabled" `
            -Current "Disabled (0)" -Expected "Disabled (0)" -Sev "High" -CISControl "18.5.4"
    } else {
        Add-Check -Category "DNS Client" -Status "Failed" -Message "Multicast name resolution NOT disabled" `
            -Current $(if($null -eq $turnOffMulticast){"Not Set"}else{"$turnOffMulticast"}) -Expected "0" -Sev "High" `
            -Remediation "New-Item -Path '$dnsPath' -Force; Set-ItemProperty -Path '$dnsPath' -Name 'EnableMulticast' -Value 0" `
            -CISControl "18.5.4"
    }
    
    # CIS 18.9 - Windows Components
    # Many are covered in Core module, adding additional ones
    
    # CIS 18.9.6 - Credential UI
    $credUIPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"
    $enumerateAdmin = (Get-ItemProperty -Path $credUIPath -Name "EnumerateAdministrators" -ErrorAction SilentlyContinue).EnumerateAdministrators
    if($enumerateAdmin -eq 0){
        Add-Check -Category "Credential UI" -Status "Passed" -Message "Do not enumerate admin accounts" `
            -Current "Disabled (0)" -Expected "0" -Sev "Medium" -CISControl "18.9.6.1"
    } else {
        Add-Check -Category "Credential UI" -Status "Failed" -Message "Enumerating admin accounts NOT disabled" `
            -Current $(if($null -eq $enumerateAdmin){"Not Set"}else{"$enumerateAdmin"}) -Expected "0" -Sev "Medium" `
            -Remediation "New-Item -Path '$credUIPath' -Force; Set-ItemProperty -Path '$credUIPath' -Name 'EnumerateAdministrators' -Value 0" `
            -CISControl "18.9.6.1"
    }
    
    # CIS 18.9.14 - Event Log Service
    foreach($log in @('Application','Security','System')){
        $logPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$log"
        
        $maxSize = (Get-ItemProperty -Path $logPath -Name "MaxSize" -ErrorAction SilentlyContinue).MaxSize
        $expectedSize = if($log -eq 'Security'){196608}else{32768} # 192MB for Security, 32MB others
        
        if($maxSize -ge $expectedSize){
            Add-Check -Category "Event Log" -Status "Passed" -Message "$log log max size OK" `
                -Current "$maxSize KB" -Expected "$expectedSize+ KB" -Sev "Low" -CISControl "18.9.14.$($log[0])"
        } else {
            Add-Check -Category "Event Log" -Status "Warnings" -Message "$log log max size small" `
                -Current $(if($maxSize){"$maxSize KB"}else{"Default"}) -Expected "$expectedSize+ KB" -Sev "Low" `
                -CISControl "18.9.14.$($log[0])"
        }
    }
    
    # CIS 18.9.26 - Logon
    $logonPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    $disableCAD = (Get-ItemProperty -Path $logonPath -Name "DisableCAD" -ErrorAction SilentlyContinue).DisableCAD
    if($disableCAD -eq 0 -or $null -eq $disableCAD){
        Add-Check -Category "Logon" -Status "Passed" -Message "Ctrl+Alt+Del requirement enforced" `
            -Current "Required" -Expected "Required" -Sev "Low" -CISControl "18.9.26.1"
    } else {
        Add-Check -Category "Logon" -Status "Failed" -Message "Ctrl+Alt+Del NOT required" `
            -Current "Not Required" -Expected "Required" -Sev "Low" `
            -Remediation "Set-ItemProperty -Path '$logonPath' -Name 'DisableCAD' -Value 0" `
            -CISControl "18.9.26.1"
    }
    
    # CIS 18.9.30 - OneDrive
    $oneDrivePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    $disableFileSyncNGSC = (Get-ItemProperty -Path $oneDrivePath -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue).DisableFileSyncNGSC
    # Note: This is optional based on organization policy
    
    # CIS 18.9.44 - Windows Defender Application Guard
    # Requires special hardware/features
    
    # CIS 18.9.47 - Windows Installer
    $installerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $alwaysInstallElevated = (Get-ItemProperty -Path $installerPath -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
    if($alwaysInstallElevated -eq 0 -or $null -eq $alwaysInstallElevated){
        Add-Check -Category "Windows Installer" -Status "Passed" -Message "Always install elevated is disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" -CISControl "18.9.47.1"
    } else {
        Add-Check -Category "Windows Installer" -Status "Failed" -Message "Always install elevated is ENABLED" `
            -Current "Enabled" -Expected "Disabled" -Sev "High" `
            -Details "Allows privilege escalation" `
            -Remediation "Set-ItemProperty -Path '$installerPath' -Name 'AlwaysInstallElevated' -Value 0" `
            -CISControl "18.9.47.1"
    }
    
    # CIS 18.9.80 - Windows PowerShell (additional)
    $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $scriptBlockLogging = (Get-ItemProperty -Path $psPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if($scriptBlockLogging -eq 1){
        Add-Check -Category "PowerShell" -Status "Passed" -Message "Script block logging enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "Medium" -CISControl "18.9.99.1.1"
    } else {
        Add-Check -Category "PowerShell" -Status "Warnings" -Message "Script block logging not enabled" `
            -Current "Disabled" -Expected "Enabled" -Sev "Medium" `
            -Details "Helps with security monitoring" -CISControl "18.9.99.1.1"
    }
    
    # CIS 18.9.102 - Windows Update
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $auPath = "$wuPath\AU"
    
    $noAutoRebootWithLoggedOnUsers = (Get-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue).NoAutoRebootWithLoggedOnUsers
    if($noAutoRebootWithLoggedOnUsers -eq 0 -or $null -eq $noAutoRebootWithLoggedOnUsers){
        Add-Check -Category "Windows Update" -Status "Passed" -Message "Auto-reboot allowed even with logged-on users" `
            -Current "Allowed" -Expected "Allowed" -Sev "Low" -CISControl "18.9.102.1.2"
    }
    
    Write-Host "CIS checks complete: $($results.Passed.Count) passed, $($results.Failed.Count) failed" -ForegroundColor Green
    return $results
}
