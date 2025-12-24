# Windows-Security-Audit-Script.ps1
# Comprehensive Windows Security Audit Script
# Version: 5.0
# GitHub: https://github.com/Sandler73/Windows-Security-Audit-Script

<#
.SYNOPSIS
    Comprehensive Windows security audit script supporting multiple compliance frameworks.

.DESCRIPTION
    This script audits Windows systems against multiple security frameworks including:
    - Core Security (baseline checks)
    - CIS Benchmarks
    - Microsoft Security Baseline
    - NIST Cybersecurity Framework
    - DISA STIGs
    - NSA Cybersecurity Guidance
    - CISA Best Practices

.PARAMETER Modules
    Comma-separated list of modules to run. Available: Core,CIS,MS,NIST,STIG,NSA,CISA,All
    Default: All

.PARAMETER OutputFormat
    Output format: HTML, CSV, JSON, or Console
    Default: HTML

.PARAMETER OutputPath
    Path for output file (for HTML, CSV, JSON formats)
    Default: .\Security-Audit-Report-[timestamp].[ext]

.PARAMETER RemediateIssues
    Attempt to automatically remediate failed checks where possible

.PARAMETER Verbose
    Enable verbose output during execution

.EXAMPLE
    .\Windows-Security-Audit-Script.ps1
    Run all modules with HTML output

.EXAMPLE
    .\Windows-Security-Audit-Script.ps1 -Modules Core,NIST,CISA -OutputFormat CSV
    Run specific modules and output to CSV

.EXAMPLE
    .\Windows-Security-Audit-Script.ps1 -RemediateIssues
    Run audit and attempt to fix issues

.NOTES
    Requires: Windows 10/11 or Windows Server 2016+, PowerShell 5.1+
    Run as Administrator for complete results
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Core","CIS","MS","NIST","STIG","NSA","CISA","All")]
    [string[]]$Modules = @("All"),
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("HTML","CSV","JSON","Console")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$RemediateIssues
    
#    [Parameter(Mandatory=$false)]
#    [switch]$Verbose
)

# ============================================================================
# Script Configuration
# ============================================================================
$ErrorActionPreference = "Continue"
$script:ScriptVersion = "5.0"
$script:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# ============================================================================
# Banner
# ============================================================================
function Show-Banner {
    Write-Host "`n========================================================================================================" -ForegroundColor Cyan
    Write-Host "                        Windows Security Audit Script v$script:ScriptVersion" -ForegroundColor Cyan
    Write-Host "                   Comprehensive Multi-Framework Security Assessment" -ForegroundColor Cyan
    Write-Host "========================================================================================================" -ForegroundColor Cyan
    Write-Host "`nSupported Frameworks:" -ForegroundColor White
    Write-Host "  • Core Security Baseline" -ForegroundColor Gray
    Write-Host "  • CIS Benchmarks" -ForegroundColor Gray
    Write-Host "  • Microsoft Security Baseline" -ForegroundColor Gray
    Write-Host "  • NIST Cybersecurity Framework" -ForegroundColor Gray
    Write-Host "  • DISA STIGs (Security Technical Implementation Guides)" -ForegroundColor Gray
    Write-Host "  • NSA Cybersecurity Guidance" -ForegroundColor Gray
    Write-Host "  • CISA Best Practices" -ForegroundColor Gray
    Write-Host "`n========================================================================================================`n" -ForegroundColor Cyan
}

# ============================================================================
# Prerequisites Check
# ============================================================================
function Test-Prerequisites {
    Write-Host "[*] Checking prerequisites..." -ForegroundColor Yellow
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-Host "[!] PowerShell 5.1 or higher is required. Current version: $psVersion" -ForegroundColor Red
        return $false
    }
    Write-Host "[+] PowerShell version: $psVersion" -ForegroundColor Green
    
    # Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Script is not running as Administrator. Some checks may fail." -ForegroundColor Yellow
        if ($RemediateIssues) {
            Write-Host "[!] ERROR: Remediation requires Administrator privileges. Exiting." -ForegroundColor Red
            return $false
        }
        Write-Host "[!] For complete results, run as Administrator." -ForegroundColor Yellow
    } else {
        Write-Host "[+] Running with Administrator privileges" -ForegroundColor Green
    }
    
    # Check OS version
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-Host "[+] Operating System: $($os.Caption) (Build $($os.BuildNumber))" -ForegroundColor Green
    
    return $true
}

# ============================================================================
# Module Management
# ============================================================================
function Get-AvailableModules {
    return @{
        "Core" = "Module-Core.ps1"
        "CIS" = "Module-CIS.ps1"
        "MS" = "Module-MS.ps1"
        "NIST" = "Module-NIST.ps1"
        "STIG" = "Module-STIG.ps1"
        "NSA" = "Module-NSA.ps1"
        "CISA" = "Module-CISA.ps1"
    }
}

function Test-ModuleExists {
    param([string]$ModuleName)
    
    $availableModules = Get-AvailableModules
    if (-not $availableModules.ContainsKey($ModuleName)) {
        return $false
    }
    
    $modulePath = Join-Path $script:ScriptPath $availableModules[$ModuleName]
    return (Test-Path $modulePath)
}

function Invoke-SecurityModule {
    param(
        [string]$ModuleName,
        [hashtable]$SharedData
    )
    
    $availableModules = Get-AvailableModules
    $modulePath = Join-Path $script:ScriptPath $availableModules[$ModuleName]
    
    if (-not (Test-Path $modulePath)) {
        Write-Host "[!] Module not found: $ModuleName at $modulePath" -ForegroundColor Red
        Write-Host "[!] Expected location: $modulePath" -ForegroundColor Yellow
        return $null
    }
    
    try {
        Write-Host "`n[*] Executing module: $ModuleName" -ForegroundColor Cyan
        
        # Create a script block that properly passes the SharedData
        $scriptBlock = [ScriptBlock]::Create(@"
            param([hashtable]`$SharedData)
            & '$modulePath' -SharedData `$SharedData
"@)
        
        $results = Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $SharedData
        
        Write-Host "[+] Module $ModuleName completed successfully" -ForegroundColor Green
        return $results
    }
    catch {
        Write-Host "[!] Error executing module ${ModuleName}: $_" -ForegroundColor Red
        Write-Host "[!] Error details: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# ============================================================================
# Remediation Functions
# ============================================================================
function Invoke-Remediation {
    param([array]$Results)
    
    if (-not $RemediateIssues) {
        return
    }
    
    Write-Host "`n========================================================================================================" -ForegroundColor Yellow
    Write-Host "                                  REMEDIATION MODE" -ForegroundColor Yellow
    Write-Host "========================================================================================================`n" -ForegroundColor Yellow
    
    $failedResults = $Results | Where-Object { $_.Status -eq "Fail" -and $_.Remediation }
    
    if ($failedResults.Count -eq 0) {
        Write-Host "[*] No failed checks with available remediation found." -ForegroundColor Cyan
        return
    }
    
    Write-Host "[*] Found $($failedResults.Count) failed check(s) with remediation available." -ForegroundColor Yellow
    Write-Host "[*] Attempting automatic remediation..." -ForegroundColor Yellow
    
    $remediatedCount = 0
    $failedRemediationCount = 0
    
    foreach ($result in $failedResults) {
        Write-Host "`n[*] Attempting to remediate: $($result.Message)" -ForegroundColor Cyan
        Write-Host "    Category: $($result.Category)" -ForegroundColor Gray
        Write-Host "    Remediation: $($result.Remediation)" -ForegroundColor Gray
        
        # Confirm with user
        $response = Read-Host "    Apply this remediation? (Y/N)"
        if ($response -ne 'Y' -and $response -ne 'y') {
            Write-Host "    [*] Skipped by user" -ForegroundColor Yellow
            continue
        }
        
        try {
            # Execute remediation command
            $remediationScript = [ScriptBlock]::Create($result.Remediation)
            Invoke-Command -ScriptBlock $remediationScript
            Write-Host "    [+] Remediation applied successfully" -ForegroundColor Green
            $remediatedCount++
        }
        catch {
            Write-Host "    [!] Remediation failed: $_" -ForegroundColor Red
            $failedRemediationCount++
        }
    }
    
    Write-Host "`n========================================================================================================" -ForegroundColor Yellow
    Write-Host "Remediation Summary:" -ForegroundColor Yellow
    Write-Host "  Total remediable issues: $($failedResults.Count)" -ForegroundColor White
    Write-Host "  Successfully remediated: $remediatedCount" -ForegroundColor Green
    Write-Host "  Failed remediations: $failedRemediationCount" -ForegroundColor Red
    Write-Host "  Skipped by user: $($failedResults.Count - $remediatedCount - $failedRemediationCount)" -ForegroundColor Yellow
    Write-Host "========================================================================================================`n" -ForegroundColor Yellow
    
    if ($remediatedCount -gt 0) {
        Write-Host "[*] Some settings may require a system restart to take effect." -ForegroundColor Yellow
        $restart = Read-Host "Would you like to restart now? (Y/N)"
        if ($restart -eq 'Y' -or $restart -eq 'y') {
            Write-Host "[*] Restarting system in 10 seconds..." -ForegroundColor Yellow
            shutdown /r /t 10 /c "System restart after security remediation"
        }
    }
}

# ============================================================================
# Output Generation
# ============================================================================
function ConvertTo-HTMLReport {
    param([array]$AllResults, [hashtable]$ExecutionInfo)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Windows Security Audit Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        .info-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 3px solid #667eea;
        }
        .info-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .info-card h3 {
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .info-card p {
            font-size: 1.1em;
            font-weight: 600;
            color: #333;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            padding: 30px;
            background: white;
        }
        .summary-card {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .summary-card.total { background: #e3f2fd; border-left: 4px solid #2196F3; }
        .summary-card.pass { background: #e8f5e9; border-left: 4px solid #4CAF50; }
        .summary-card.fail { background: #ffebee; border-left: 4px solid #f44336; }
        .summary-card.warning { background: #fff3e0; border-left: 4px solid #ff9800; }
        .summary-card.info { background: #e1f5fe; border-left: 4px solid #00bcd4; }
        .summary-card.error { background: #f3e5f5; border-left: 4px solid #9c27b0; }
        .summary-card h3 {
            font-size: 2.5em;
            margin-bottom: 5px;
        }
        .summary-card p {
            font-size: 0.9em;
            text-transform: uppercase;
            font-weight: 600;
            opacity: 0.7;
        }
        .results {
            padding: 30px;
        }
        .module-section {
            margin-bottom: 40px;
            background: #f8f9fa;
            border-radius: 8px;
            overflow: hidden;
        }
        .module-header {
            background: #667eea;
            color: white;
            padding: 20px;
            font-size: 1.5em;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .module-header:hover {
            background: #5568d3;
        }
        .module-stats {
            font-size: 0.8em;
            opacity: 0.9;
        }
        .module-content {
            padding: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        th {
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
        }
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .status {
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
            display: inline-block;
        }
        .status-pass { background: #4CAF50; color: white; }
        .status-fail { background: #f44336; color: white; }
        .status-warning { background: #ff9800; color: white; }
        .status-info { background: #00bcd4; color: white; }
        .status-error { background: #9c27b0; color: white; }
        .details {
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }
        .remediation {
            background: #fff3cd;
            padding: 10px;
            border-left: 4px solid #ff9800;
            margin-top: 8px;
            border-radius: 4px;
            font-size: 0.9em;
            font-family: 'Courier New', monospace;
        }
        .footer {
            background: #333;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>🛡️ Windows Security Audit Report</h1>
            <div class='subtitle'>Comprehensive Multi-Framework Security Assessment</div>
        </div>
        
        <div class='info-section'>
            <div class='info-card'>
                <h3>Computer Name</h3>
                <p>$($ExecutionInfo.ComputerName)</p>
            </div>
            <div class='info-card'>
                <h3>Operating System</h3>
                <p>$($ExecutionInfo.OSVersion)</p>
            </div>
            <div class='info-card'>
                <h3>Scan Date</h3>
                <p>$($ExecutionInfo.ScanDate)</p>
            </div>
            <div class='info-card'>
                <h3>Duration</h3>
                <p>$($ExecutionInfo.Duration)</p>
            </div>
            <div class='info-card'>
                <h3>Modules Executed</h3>
                <p>$($ExecutionInfo.ModulesRun -join ', ')</p>
            </div>
        </div>
        
        <div class='summary'>
            <div class='summary-card total'>
                <h3>$($ExecutionInfo.TotalChecks)</h3>
                <p>Total Checks</p>
            </div>
            <div class='summary-card pass'>
                <h3>$($ExecutionInfo.PassCount)</h3>
                <p>Passed</p>
            </div>
            <div class='summary-card fail'>
                <h3>$($ExecutionInfo.FailCount)</h3>
                <p>Failed</p>
            </div>
            <div class='summary-card warning'>
                <h3>$($ExecutionInfo.WarningCount)</h3>
                <p>Warnings</p>
            </div>
            <div class='summary-card info'>
                <h3>$($ExecutionInfo.InfoCount)</h3>
                <p>Info</p>
            </div>
            <div class='summary-card error'>
                <h3>$($ExecutionInfo.ErrorCount)</h3>
                <p>Errors</p>
            </div>
        </div>
        
        <div class='results'>
"@

    # Group results by module
    $moduleGroups = $AllResults | Group-Object -Property Module
    
    foreach ($moduleGroup in $moduleGroups) {
        $moduleName = $moduleGroup.Name
        $moduleResults = $moduleGroup.Group
        
        $modulePass = ($moduleResults | Where-Object { $_.Status -eq "Pass" }).Count
        $moduleFail = ($moduleResults | Where-Object { $_.Status -eq "Fail" }).Count
        $moduleWarn = ($moduleResults | Where-Object { $_.Status -eq "Warning" }).Count
        
        $html += @"
            <div class='module-section'>
                <div class='module-header'>
                    <span>📋 $moduleName</span>
                    <span class='module-stats'>✓ $modulePass | ✗ $moduleFail | ⚠ $moduleWarn</span>
                </div>
                <div class='module-content'>
                    <table>
                        <tr>
                            <th style='width: 10%'>Status</th>
                            <th style='width: 25%'>Category</th>
                            <th style='width: 65%'>Finding</th>
                        </tr>
"@

        foreach ($result in $moduleResults) {
            $statusClass = "status-$($result.Status.ToLower())"
            $html += @"
                        <tr>
                            <td><span class='status $statusClass'>$($result.Status)</span></td>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($result.Category))</td>
                            <td>
                                <strong>$([System.Web.HttpUtility]::HtmlEncode($result.Message))</strong>
"@
            if ($result.Details) {
                $html += "<div class='details'>$([System.Web.HttpUtility]::HtmlEncode($result.Details))</div>"
            }
            if ($result.Remediation) {
                $html += "<div class='remediation'><strong>💡 Remediation:</strong> $([System.Web.HttpUtility]::HtmlEncode($result.Remediation))</div>"
            }
            $html += @"
                            </td>
                        </tr>
"@
        }

        $html += @"
                    </table>
                </div>
            </div>
"@
    }

    $html += @"
        </div>
        
        <div class='footer'>
            Generated by Windows Security Audit Script v$script:ScriptVersion<br>
            GitHub: <a href="https://github.com/Sandler73/Windows-Security-Audit-Script" style="color: #4fc3f7;">https://github.com/Sandler73/Windows-Security-Audit-Script</a>
        </div>
    </div>
</body>
</html>
"@

    return $html
}

function Export-Results {
    param(
        [array]$AllResults,
        [hashtable]$ExecutionInfo,
        [string]$Format,
        [string]$Path
    )
    
    # Generate default path if not specified
    if ([string]::IsNullOrEmpty($Path)) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $extension = switch ($Format) {
            "HTML" { "html" }
            "CSV" { "csv" }
            "JSON" { "json" }
            default { "txt" }
        }
        $Path = Join-Path $script:ScriptPath "Security-Audit-Report-$timestamp.$extension"
    }
    
    switch ($Format) {
        "HTML" {
            $htmlContent = ConvertTo-HTMLReport -AllResults $AllResults -ExecutionInfo $ExecutionInfo
            $htmlContent | Out-File -FilePath $Path -Encoding UTF8
            Write-Host "`n[+] HTML report saved to: $Path" -ForegroundColor Green
        }
        "CSV" {
            $AllResults | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            Write-Host "`n[+] CSV report saved to: $Path" -ForegroundColor Green
        }
        "JSON" {
            $reportData = @{
                ExecutionInfo = $ExecutionInfo
                Results = $AllResults
            }
            $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
            Write-Host "`n[+] JSON report saved to: $Path" -ForegroundColor Green
        }
        "Console" {
            # Results already displayed during execution
            Write-Host "`n[+] Console output complete" -ForegroundColor Green
        }
    }
    
    return $Path
}

# ============================================================================
# Main Execution
# ============================================================================
function Start-SecurityAudit {
    $startTime = Get-Date
    
    Show-Banner
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Host "`n[!] Prerequisites check failed. Exiting." -ForegroundColor Red
        return
    }
    
    # Determine which modules to run
    $modulesToRun = if ($Modules -contains "All") {
        @("Core", "CIS", "MS", "NIST", "STIG", "NSA", "CISA")
    } else {
        $Modules
    }
    
    Write-Host "`n[*] Modules to execute: $($modulesToRun -join ', ')" -ForegroundColor Cyan
    
    # Verify all modules exist
    $missingModules = @()
    foreach ($module in $modulesToRun) {
        if (-not (Test-ModuleExists -ModuleName $module)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Host "`n[!] WARNING: The following modules are missing from the script directory:" -ForegroundColor Yellow
        foreach ($missing in $missingModules) {
            $availableModules = Get-AvailableModules
            Write-Host "    - $($availableModules[$missing]) (Module: $missing)" -ForegroundColor Yellow
        }
        Write-Host "`n[*] Script directory: $script:ScriptPath" -ForegroundColor Cyan
        Write-Host "[*] Continuing with available modules..." -ForegroundColor Yellow
        $modulesToRun = $modulesToRun | Where-Object { $_ -notin $missingModules }
        
        if ($modulesToRun.Count -eq 0) {
            Write-Host "`n[!] No modules available to run. Exiting." -ForegroundColor Red
            return
        }
    }
    
    # Prepare shared data
    $sharedData = @{
        ComputerName = $env:COMPUTERNAME
        OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
        ScanDate = Get-Date
        IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ScriptPath = $script:ScriptPath
        RemediateIssues = $RemediateIssues.IsPresent
    }
    
    # Execute modules
    $allResults = @()
    $successfulModules = @()
    
    foreach ($module in $modulesToRun) {
        try {
            $moduleResults = Invoke-SecurityModule -ModuleName $module -SharedData $sharedData
            if ($moduleResults) {
                $allResults += $moduleResults
                $successfulModules += $module
            }
        }
        catch {
            Write-Host "[!] Failed to execute module ${module}: $_" -ForegroundColor Red
            Write-Host "[!] Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
        }
    }
    
    if ($allResults.Count -eq 0) {
        Write-Host "`n[!] No results were generated. Check that modules are correctly placed in the script directory." -ForegroundColor Red
        return
    }
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    # Calculate statistics
    $executionInfo = @{
        ComputerName = $sharedData.ComputerName
        OSVersion = $sharedData.OSVersion
        ScanDate = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
        Duration = "{0:hh\:mm\:ss}" -f $duration
        ModulesRun = $successfulModules
        TotalChecks = $allResults.Count
        PassCount = ($allResults | Where-Object { $_.Status -eq "Pass" }).Count
        FailCount = ($allResults | Where-Object { $_.Status -eq "Fail" }).Count
        WarningCount = ($allResults | Where-Object { $_.Status -eq "Warning" }).Count
        InfoCount = ($allResults | Where-Object { $_.Status -eq "Info" }).Count
        ErrorCount = ($allResults | Where-Object { $_.Status -eq "Error" }).Count
    }
    
    # Display summary
    Write-Host "`n========================================================================================================" -ForegroundColor Cyan
    Write-Host "                                    AUDIT SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================================================================================" -ForegroundColor Cyan
    Write-Host "Total Checks:    $($executionInfo.TotalChecks)" -ForegroundColor White
    Write-Host "Passed:          $($executionInfo.PassCount)" -ForegroundColor Green
    Write-Host "Failed:          $($executionInfo.FailCount)" -ForegroundColor Red
    Write-Host "Warnings:        $($executionInfo.WarningCount)" -ForegroundColor Yellow
    Write-Host "Info:            $($executionInfo.InfoCount)" -ForegroundColor Cyan
    Write-Host "Errors:          $($executionInfo.ErrorCount)" -ForegroundColor Magenta
    Write-Host "Duration:        $($executionInfo.Duration)" -ForegroundColor White
    Write-Host "========================================================================================================`n" -ForegroundColor Cyan
    
    # Perform remediation if requested
    if ($RemediateIssues) {
        Invoke-Remediation -Results $allResults
    }
    
    # Export results
    if ($OutputFormat -ne "Console") {
        $outputPath = Export-Results -AllResults $allResults -ExecutionInfo $executionInfo -Format $OutputFormat -Path $OutputPath
        
        if ($OutputFormat -eq "HTML" -and (Test-Path $outputPath)) {
            Write-Host "[*] Opening report in default browser..." -ForegroundColor Cyan
            Start-Process $outputPath
        }
    }
    
    Write-Host "`n[+] Audit completed successfully!" -ForegroundColor Green
    Write-Host "[*] GitHub: https://github.com/Sandler73/Windows-Security-Audit-Script" -ForegroundColor Cyan
}

# ============================================================================
# Script Entry Point
# ============================================================================
try {
    Start-SecurityAudit
}
catch {
    Write-Host "`n[!] Fatal error during audit execution:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "`nStack Trace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace -ForegroundColor Yellow
}
