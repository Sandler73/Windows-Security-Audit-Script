# Windows-Security-Audit-Script.ps1
# Comprehensive Windows Security Audit Script
# Version: 5.2
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
    
.CHANGES in v5.1
    - Enhanced statistics tracking and validation
    - Fixed module result counting issues
    - Improved error handling and logging
    - Added result normalization for consistency
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
)
# ============================================================================
# Script Configuration
# ============================================================================
$ErrorActionPreference = "Continue"
$script:ScriptVersion = "5.1"
$script:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
# Valid status values for normalization
$script:ValidStatusValues = @("Pass", "Fail", "Warning", "Info", "Error")
# Statistics tracking
$script:StatisticsLog = @{
    ValidationIssues = @()
    NormalizedResults = 0
    ModuleStats = @{}
}
# ============================================================================
# Banner
# ============================================================================
function Show-Banner {
    Write-Host "`n========================================================================================================" -ForegroundColor Cyan
    Write-Host "                        Windows Security Audit Script v$script:ScriptVersion" -ForegroundColor Cyan
    Write-Host "                   Comprehensive Multi-Framework Security Assessment" -ForegroundColor Cyan
    Write-Host "========================================================================================================" -ForegroundColor Cyan
    Write-Host "`nSupported Frameworks:" -ForegroundColor White
    Write-Host "  - Core Security Baseline" -ForegroundColor Gray
    Write-Host "  - CIS Benchmarks" -ForegroundColor Gray
    Write-Host "  - Microsoft Security Baseline" -ForegroundColor Gray
    Write-Host "  - NIST Cybersecurity Framework" -ForegroundColor Gray
    Write-Host "  - DISA STIGs" -ForegroundColor Gray
    Write-Host "  - NSA Cybersecurity Guidance" -ForegroundColor Gray
    Write-Host "  - CISA Best Practices" -ForegroundColor Gray
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
        Write-Host "[!] PowerShell 5.1 or higher required. Current: $psVersion" -ForegroundColor Red
        return $false
    }
    Write-Host "[+] PowerShell version: $psVersion" -ForegroundColor Green
    # Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator" -ForegroundColor Yellow
        if ($RemediateIssues) {
            Write-Host "[!] ERROR: Remediation requires Administrator privileges" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "[+] Running with Administrator privileges" -ForegroundColor Green
    }
    # Check OS version
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-Host "[+] Operating System: $($os.Caption) (Build $($os.BuildNumber))" -ForegroundColor Green
    return $true
}
# ============================================================================
# Result Validation and Normalization Functions
# ============================================================================
function Test-ResultObject {
    <#
    .SYNOPSIS
        Validates that a result object has all required properties and valid values.
    #>
    param([PSCustomObject]$Result, [string]$ModuleName)
    $isValid = $true
    $issues = @()
	# Required properties
    $requiredProperties = @("Module", "Category", "Message", "Status")
    foreach ($prop in $requiredProperties) {
        if (-not $Result.PSObject.Properties[$prop]) {
            $isValid = $false
            $issues += "Missing: $prop"
        }
    }
	# Validate Status value
    if ($Result.Status -and $Result.Status -notin $script:ValidStatusValues) {
        $isValid = $false
        $issues += "Invalid Status: '$($Result.Status)'"
    }
	# Log validation issues
    if (-not $isValid) {
        $script:StatisticsLog.ValidationIssues += [PSCustomObject]@{
            Module = $ModuleName
            Issues = $issues -join "; "
            Timestamp = Get-Date
        }
    }
    return $isValid
}
# ============================================================================
# Data Repair Function
# ============================================================================
function Repair-ResultObject {
    <#
    .SYNOPSIS
        Attempts to repair/normalize a result object with missing or invalid properties.
    #>
    param([PSCustomObject]$Result, [string]$ModuleName)
    $normalized = $false
	# Ensure Module property exists
    if (-not $Result.Module) {
        $Result | Add-Member -NotePropertyName "Module" -NotePropertyValue $ModuleName -Force
        $normalized = $true
    }
	# Ensure Category exists
    if (-not $Result.Category) {
        $Result | Add-Member -NotePropertyName "Category" -NotePropertyValue "Uncategorized" -Force
        $normalized = $true
    }
	# Ensure Message exists
    if (-not $Result.Message) {
        $Result | Add-Member -NotePropertyName "Message" -NotePropertyValue "No message" -Force
        $normalized = $true
    }
	# Normalize Status value (case-insensitive matching)
    if ($Result.Status) {
		# Try case-insensitive match
        $matchedStatus = $script:ValidStatusValues | Where-Object { $_.ToLower() -eq $Result.Status.ToLower() } | Select-Object -First 1
        if ($matchedStatus -and $Result.Status -ne $matchedStatus) {
            $Result.Status = $matchedStatus
            $normalized = $true
        } elseif (-not $matchedStatus) {
            $Result.Status = "Error"
            $normalized = $true
        }
    } else {
		# Invalid status - default to Error
        $Result | Add-Member -NotePropertyName "Status" -NotePropertyValue "Error" -Force
        $normalized = $true
    }
	# Ensure optional properties exist
    if (-not $Result.Details) {
        $Result | Add-Member -NotePropertyName "Details" -NotePropertyValue "" -Force
    }
    if (-not $Result.Remediation) {
        $Result | Add-Member -NotePropertyName "Remediation" -NotePropertyValue "" -Force
    }
    if ($normalized) { $script:StatisticsLog.NormalizedResults++ }
    return $Result
}
# ============================================================================
# Data Validation Function
# ============================================================================
function Get-ValidatedResults {
    <#
    .SYNOPSIS
        Validates and normalizes an array of results from a module.
    #>
    param([array]$Results, [string]$ModuleName)
    if (-not $Results -or $Results.Count -eq 0) {
        Write-Host "[!] Module $ModuleName returned no results" -ForegroundColor Yellow
        return @()
    }
    $validatedResults = @()
    foreach ($result in $Results) {
        if (Test-ResultObject -Result $result -ModuleName $ModuleName) {
            $validatedResults += $result
        } else {
			# Try to repair the result
            $repairedResult = Repair-ResultObject -Result $result -ModuleName $ModuleName
            if (Test-ResultObject -Result $repairedResult -ModuleName $ModuleName) {
                $validatedResults += $repairedResult
            }
        }
    }
    return $validatedResults
}
# ============================================================================
# Data Tabulation Function
# ============================================================================
function Get-ModuleStatistics {
    <#
    .SYNOPSIS
        Calculates accurate statistics for a module's results.
    #>
    param([array]$Results)
    return [PSCustomObject]@{
        Total = $Results.Count
        Pass = ($Results | Where-Object { $_.Status -eq "Pass" }).Count
        Fail = ($Results | Where-Object { $_.Status -eq "Fail" }).Count
        Warning = ($Results | Where-Object { $_.Status -eq "Warning" }).Count
        Info = ($Results | Where-Object { $_.Status -eq "Info" }).Count
        Error = ($Results | Where-Object { $_.Status -eq "Error" }).Count
    }
}
# ============================================================================
# Module Management
# ============================================================================
function Get-AvailableModules {
    return @{
        "Core" = "Modules\Module-Core.ps1"
        "CIS" = "Modules\Module-CIS.ps1"
        "MS" = "Modules\Module-MS.ps1"
        "NIST" = "Modules\Module-NIST.ps1"
        "STIG" = "Modules\Module-STIG.ps1"
        "NSA" = "Modules\Module-NSA.ps1"
        "CISA" = "Modules\Module-CISA.ps1"
    }
}
# ============================================================================
# Module Detection Function
# ============================================================================
function Test-ModuleExists {
    param([string]$ModuleName)
    $availableModules = Get-AvailableModules
    if (-not $availableModules.ContainsKey($ModuleName)) { return $false }
    $modulePath = Join-Path $script:ScriptPath $availableModules[$ModuleName]
    return (Test-Path $modulePath)
}
# ============================================================================
# Module Data Security Function
# ============================================================================
function Invoke-SecurityModule {
    param([string]$ModuleName, [hashtable]$SharedData)
    $availableModules = Get-AvailableModules
    $modulePath = Join-Path $script:ScriptPath $availableModules[$ModuleName]
    if (-not (Test-Path $modulePath)) {
        Write-Host "[!] Module not found: $ModuleName" -ForegroundColor Red
        return $null
    }
    try {
        Write-Host "`n[*] Executing module: $ModuleName" -ForegroundColor Cyan
        $scriptBlock = [ScriptBlock]::Create("param([hashtable]`$SharedData); & '$modulePath' -SharedData `$SharedData")
        $results = Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $SharedData
        # Validate and normalize results
		$validatedResults = Get-ValidatedResults -Results $results -ModuleName $ModuleName
		# Calculate and display module statistics
        $moduleStats = Get-ModuleStatistics -Results $validatedResults
        $script:StatisticsLog.ModuleStats[$ModuleName] = $moduleStats
        Write-Host "[+] Module $ModuleName completed: $($moduleStats.Total) checks ($($moduleStats.Pass) pass, $($moduleStats.Fail) fail, $($moduleStats.Warning) warning, $($moduleStats.Info) info, $($moduleStats.Error) error)" -ForegroundColor Green
        return $validatedResults
    }
    catch {
        Write-Host "[!] Error executing module ${ModuleName}: $_" -ForegroundColor Red
        return $null
    }
}
# ============================================================================
# Remediation Functions
# ============================================================================
function Invoke-Remediation {
    param([array]$Results)
    if (-not $RemediateIssues) { return }
    Write-Host "`n=======================================================================================================" -ForegroundColor Yellow
    Write-Host "                                  REMEDIATION MODE" -ForegroundColor Yellow
    Write-Host "========================================================================================================`n" -ForegroundColor Yellow
    $failedResults = $Results | Where-Object { $_.Status -eq "Fail" -and $_.Remediation }
    if ($failedResults.Count -eq 0) {
        Write-Host "[*] No failed checks with remediation available" -ForegroundColor Cyan
        return
    }
    Write-Host "[*] Found $($failedResults.Count) failed check(s) with remediation available" -ForegroundColor Yellow
    $remediatedCount = 0
    $failedRemediationCount = 0
    foreach ($result in $failedResults) {
        Write-Host "`n[*] Remediate: $($result.Message)" -ForegroundColor Cyan
        Write-Host "    Category: $($result.Category)" -ForegroundColor Gray
        Write-Host "    Remediation: $($result.Remediation)" -ForegroundColor Gray
        $response = Read-Host "    Apply? (Y/N)"
        if ($response -eq 'Y' -or $response -eq 'y') {
            try {
                $remediationScript = [ScriptBlock]::Create($result.Remediation)
                Invoke-Command -ScriptBlock $remediationScript
                Write-Host "    [+] Applied successfully" -ForegroundColor Green
                $remediatedCount++
            }
            catch {
                Write-Host "    [!] Failed: $_" -ForegroundColor Red
                $failedRemediationCount++
            }
        }
    }
    Write-Host "`n========================================================================================================" -ForegroundColor Yellow
    Write-Host "Remediation Summary:" -ForegroundColor Yellow
    Write-Host "  Successfully remediated: $remediatedCount" -ForegroundColor Green
    Write-Host "  Failed: $failedRemediationCount" -ForegroundColor Red
    Write-Host "========================================================================================================`n" -ForegroundColor Yellow
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
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-gradient-start: #667eea;
            --bg-gradient-end: #764ba2;
            --text-primary: #333333;
            --text-secondary: #666666;
            --border-color: #e0e0e0;
            --card-shadow: rgba(0,0,0,0.1);
            --header-hover: #5568d3;
            --row-hover: #f5f5f5;
        }
        [data-theme="dark"] {
            --bg-primary: #1e1e1e;
            --bg-secondary: #2d2d2d;
            --bg-gradient-start: #4a5568;
            --bg-gradient-end: #2d3748;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --border-color: #404040;
            --card-shadow: rgba(0,0,0,0.3);
            --header-hover: #3a4556;
            --row-hover: #353535;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            padding: 20px;
            color: var(--text-primary);
            transition: all 0.3s;
        }
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            background: var(--bg-primary);
            border: 2px solid var(--border-color);
            border-radius: 25px;
            padding: 10px 20px;
            cursor: pointer;
            box-shadow: 0 4px 12px var(--card-shadow);
            font-weight: 600;
            color: var(--text-primary);
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: var(--bg-primary);
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { font-size: 1.2em; opacity: 0.9; }
        .info-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: var(--bg-secondary);
            border-bottom: 3px solid var(--bg-gradient-start);
        }
        .info-card {
            background: var(--bg-primary);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--card-shadow);
        }
        .info-card h3 {
            color: var(--bg-gradient-start);
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .info-card p { font-size: 1.1em; font-weight: 600; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            padding: 30px;
        }
        .summary-card {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--card-shadow);
        }
        .summary-card.total { background: #e3f2fd; border-left: 4px solid #2196F3; color: #1565c0; }
        .summary-card.pass { background: #e8f5e9; border-left: 4px solid #4CAF50; color: #2e7d32; }
        .summary-card.fail { background: #ffebee; border-left: 4px solid #f44336; color: #c62828; }
        .summary-card.warning { background: #fff3e0; border-left: 4px solid #ff9800; color: #e65100; }
        .summary-card.info { background: #e1f5fe; border-left: 4px solid #00bcd4; color: #006064; }
        .summary-card.error { background: #f3e5f5; border-left: 4px solid #9c27b0; color: #6a1b9a; }
        [data-theme="dark"] .summary-card.total { background: #1e3a5f; color: #90caf9; }
        [data-theme="dark"] .summary-card.pass { background: #1b5e20; color: #a5d6a7; }
        [data-theme="dark"] .summary-card.fail { background: #5f1c1c; color: #ef9a9a; }
        [data-theme="dark"] .summary-card.warning { background: #5f3d00; color: #ffcc80; }
        [data-theme="dark"] .summary-card.info { background: #004d56; color: #80deea; }
        [data-theme="dark"] .summary-card.error { background: #4a148c; color: #ce93d8; }
        .summary-card h3 { font-size: 2.5em; margin-bottom: 5px; }
        .summary-card p { font-size: 0.9em; text-transform: uppercase; font-weight: 600; opacity: 0.7; }
        .results { padding: 30px; }
        .module-section {
            margin-bottom: 40px;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }
        .module-header {
            background: var(--bg-gradient-start);
            color: white;
            padding: 20px;
            font-size: 1.5em;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .module-header:hover { background: var(--header-hover); }
        .module-stats { font-size: 0.8em; }
        .module-content { padding: 20px; }
        .toggle-icon { 
            transition: transform 0.3s; 
            display: inline-block;
            width: 0;
            height: 0;
            border-left: 8px solid transparent;
            border-right: 8px solid transparent;
            border-top: 12px solid white;
            margin-left: 10px;
        }
        .module-section.collapsed .toggle-icon { transform: rotate(-90deg); }
        .module-section.collapsed .module-content { display: none; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            background: var(--bg-primary);
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--card-shadow);
        }
        th {
            background: var(--bg-gradient-start);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
            cursor: pointer;
        }
        th:first-child { cursor: default; }
        td {
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        tr:hover { background: var(--row-hover); }
        .filter-row input {
            width: 100%;
            padding: 8px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--bg-primary);
            color: var(--text-primary);
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
        .details { color: var(--text-secondary); font-size: 0.9em; margin-top: 5px; }
        .remediation {
            background: #fff3cd;
            padding: 10px;
            border-left: 4px solid #ff9800;
            margin-top: 8px;
            border-radius: 4px;
            font-size: 0.9em;
            font-family: 'Courier New', monospace;
            color: #856404;
        }
        .export-btn {
            margin: 10px 10px 0 0;
            padding: 8px 16px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
        }
        .export-btn:hover { background: #45a049; }
        .export-btn.secondary { background: #2196F3; }
        .export-btn.secondary:hover { background: #1e88e5; }
        .global-exports {
            text-align: center;
            margin-bottom: 20px;
            padding: 20px;
            background: var(--bg-secondary);
            border-radius: 8px;
        }
        .footer {
            background: #333;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }
        .footer a { color: #4fc3f7; text-decoration: none; }
        
        /* Modal styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 2000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        .modal-content {
            background-color: var(--bg-primary);
            margin: 15% auto;
            padding: 30px;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            width: 400px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        .modal-header {
            font-size: 1.5em;
            font-weight: 600;
            margin-bottom: 20px;
            color: var(--text-primary);
        }
        .format-option {
            display: block;
            padding: 15px;
            margin: 10px 0;
            background: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            color: var(--text-primary);
            font-weight: 600;
        }
        .format-option:hover {
            background: var(--bg-gradient-start);
            color: white;
            transform: translateX(5px);
        }
        .modal-close {
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: var(--text-secondary);
        }
        .modal-close:hover {
            color: var(--text-primary);
        }
    </style>
</head>
<body>
    <button class='theme-toggle' onclick='toggleTheme()'>Toggle Dark Mode</button>
    <div class='container'>
        <div class='header'>
            <h1>Windows Security Audit Report</h1>
            <div class='subtitle'>Comprehensive Multi-Framework Security Assessment</div>
        </div>
        <div class='info-section'>
            <div class='info-card'><h3>Computer Name</h3><p>$($ExecutionInfo.ComputerName)</p></div>
            <div class='info-card'><h3>Operating System</h3><p>$($ExecutionInfo.OSVersion)</p></div>
            <div class='info-card'><h3>Scan Date</h3><p>$($ExecutionInfo.ScanDate)</p></div>
            <div class='info-card'><h3>Duration</h3><p>$($ExecutionInfo.Duration)</p></div>
            <div class='info-card'><h3>Modules Executed</h3><p>$($ExecutionInfo.ModulesRun -join ', ')</p></div>
        </div>
        <div class='summary'>
            <div class='summary-card total'><h3>$($ExecutionInfo.TotalChecks)</h3><p>Total Checks</p></div>
            <div class='summary-card pass'><h3>$($ExecutionInfo.PassCount)</h3><p>Passed</p></div>
            <div class='summary-card fail'><h3>$($ExecutionInfo.FailCount)</h3><p>Failed</p></div>
            <div class='summary-card warning'><h3>$($ExecutionInfo.WarningCount)</h3><p>Warnings</p></div>
            <div class='summary-card info'><h3>$($ExecutionInfo.InfoCount)</h3><p>Info</p></div>
            <div class='summary-card error'><h3>$($ExecutionInfo.ErrorCount)</h3><p>Errors</p></div>
        </div>
        <div class='results'>
            <div class='global-exports'>
                <h3 style='margin-bottom: 15px; color: var(--text-primary);'>Global Export Options</h3>
                <button class='export-btn' onclick='showExportModal("all")'>Export All</button>
                <button class='export-btn secondary' onclick='showExportModal("selected")'>Export Selected</button>
            </div>
"@
    $moduleGroups = $AllResults | Group-Object -Property Module
    foreach ($moduleGroup in $moduleGroups) {
        $moduleName = $moduleGroup.Name
        $moduleResults = $moduleGroup.Group
        $moduleStats = Get-ModuleStatistics -Results $moduleResults
        
        $html += @"
            <div class='module-section'>
                <div class='module-header' onclick='toggleModule(this)'>
                    <span>MODULE: $moduleName</span>
                    <span class='module-stats'>Pass: $($moduleStats.Pass) | Fail: $($moduleStats.Fail) | Warning: $($moduleStats.Warning) | Info: $($moduleStats.Info) | Error: $($moduleStats.Error)</span>
                    <span class='toggle-icon'></span>
                </div>
                <div class='module-content'>
                    <table id='table-$moduleName'>
                        <thead>
                            <tr>
                                <th style='width: 5%'><input type='checkbox' class='select-all' onchange='toggleSelectAll(this)'></th>
                                <th style='width: 10%' onclick='sortTable(this)'>Status</th>
                                <th style='width: 25%' onclick='sortTable(this)'>Category</th>
                                <th style='width: 60%' onclick='sortTable(this)'>Finding</th>
                            </tr>
                            <tr class='filter-row'>
                                <td></td>
                                <td><input type='text' placeholder='Filter' onkeyup='filterTable(this)'></td>
                                <td><input type='text' placeholder='Filter' onkeyup='filterTable(this)'></td>
                                <td><input type='text' placeholder='Filter' onkeyup='filterTable(this)'></td>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($result in $moduleResults) {
            $statusClass = "status-$($result.Status.ToLower())"
            $html += @"
                            <tr>
                                <td><input type='checkbox' class='row-checkbox'></td>
                                <td><span class='status $statusClass'>$($result.Status)</span></td>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($result.Category))</td>
                                <td><strong>$([System.Web.HttpUtility]::HtmlEncode($result.Message))</strong>
"@
            if ($result.Details) {
                $html += "<div class='details'>$([System.Web.HttpUtility]::HtmlEncode($result.Details))</div>"
            }
            if ($result.Remediation) {
                $html += "<div class='remediation'><strong>REMEDIATION:</strong> $([System.Web.HttpUtility]::HtmlEncode($result.Remediation))</div>"
            }
            $html += "</td></tr>"
        }
        $html += @"
                        </tbody>
                    </table>
                    <button class='export-btn' onclick='showExportModal("module", "table-$moduleName")'>Export Module</button>
                    <button class='export-btn secondary' onclick='showExportModal("module-selected", "table-$moduleName")'>Export Selected from Module</button>
                </div>
            </div>
"@
    }
    $html += @"
        </div>
        <div class='footer'>
            Generated by Windows Security Audit Script v$script:ScriptVersion<br>
            GitHub: <a href='https://github.com/Sandler73/Windows-Security-Audit-Script'>GitHub Repository</a>
        </div>
    </div>
    <div id='exportModal' class='modal'>
        <div class='modal-content'>
            <span class='modal-close' onclick='closeExportModal()'>&times;</span>
            <div class='modal-header'>Select Export Format</div>
            <div class='format-option' onclick='executeExport("csv")'>CSV</div>
            <div class='format-option' onclick='executeExport("excel")'>Excel</div>
            <div class='format-option' onclick='executeExport("json")'>JSON</div>
            <div class='format-option' onclick='executeExport("xml")'>XML</div>
            <div class='format-option' onclick='executeExport("txt")'>TXT</div>
        </div>
    </div>
    <script>
        let currentExportMode = null;
        let currentTableId = null;
        
        function toggleTheme() {
            const html = document.documentElement;
            const theme = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
        }
        
        document.addEventListener('DOMContentLoaded', () => {
            const theme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', theme);
        });
        
        function toggleModule(header) {
            header.parentElement.classList.toggle('collapsed');
        }
        
        function toggleSelectAll(checkbox) {
            const table = checkbox.closest('table');
            table.querySelectorAll('tbody .row-checkbox').forEach(cb => cb.checked = checkbox.checked);
        }
        
        function sortTable(th) {
            const table = th.closest('table');
            const tbody = table.querySelector('tbody');
            const colIndex = Array.from(th.parentElement.children).indexOf(th);
            const rows = Array.from(tbody.rows);
            const isAsc = th.classList.contains('asc');
            th.parentElement.querySelectorAll('th').forEach(h => h.classList.remove('asc', 'desc'));
            th.classList.add(isAsc ? 'desc' : 'asc');
            rows.sort((a, b) => {
                const aText = a.cells[colIndex].textContent.trim();
                const bText = b.cells[colIndex].textContent.trim();
                return isAsc ? bText.localeCompare(aText) : aText.localeCompare(bText);
            });
            rows.forEach(row => tbody.appendChild(row));
        }
        
        function filterTable(input) {
            const table = input.closest('table');
            const colIndex = Array.from(input.parentElement.parentElement.children).indexOf(input.parentElement);
            const filterValue = input.value.toLowerCase();
            table.querySelectorAll('tbody tr').forEach(row => {
                const cellText = row.cells[colIndex].textContent.toLowerCase();
                row.style.display = cellText.includes(filterValue) ? '' : 'none';
            });
        }
        
        // Modal functions
        function showExportModal(mode, tableId = null) {
            currentExportMode = mode;
            currentTableId = tableId;
            document.getElementById('exportModal').style.display = 'block';
        }
        
        function closeExportModal() {
            document.getElementById('exportModal').style.display = 'none';
            currentExportMode = null;
            currentTableId = null;
        }
        
        function executeExport(format) {
            console.log('executeExport called', currentExportMode, currentTableId, format);
            
            switch(currentExportMode) {
                case 'all':
                    exportAll(format);
                    break;
                case 'selected':
                    exportSelected(format);
                    break;
                case 'module':
                    exportModule(currentTableId, format);
                    break;
                case 'module-selected':
                    exportModuleSelected(currentTableId, format);
                    break;
                default:
                    console.warn('Unknown export mode:', currentExportMode);
            }
            
            closeExportModal();
        }
        
        function getCellText(cell) {
            let text = '';
            const strong = cell.querySelector('strong');
            if (strong) {
                text += strong.textContent.trim() + '\\n\\n';
            }
            const details = cell.querySelector('.details');
            if (details) {
                text += 'Details: ' + details.textContent.trim() + '\\n\\n';
            }
            const remediation = cell.querySelector('.remediation');
            if (remediation) {
                text += remediation.textContent.trim() + '\\n';
            }
            return text.trim();
        }
        // Get data from table
        function getTableData(tableId, selectedOnly = false) {
            const table = document.getElementById(tableId);
            const moduleName = table.closest('.module-section').querySelector('.module-header span:first-child').textContent.replace('MODULE: ', '').trim();
            const headers = ['Status', 'Category', 'Finding'];
    
            let rows;
            if (selectedOnly) {
                const selected = table.querySelectorAll('tbody .row-checkbox:checked');
                rows = Array.from(selected).map(cb => cb.closest('tr'));
        } else {
            rows = Array.from(table.querySelectorAll('tbody tr')).filter(row => row.style.display !== 'none');
        }
    
        const data = rows.map(row => 
            Array.from(row.cells).slice(1).map((cell, cellIndex) => {
                if (cellIndex === 0) {
                    return cell.querySelector('.status') ? cell.querySelector('.status').textContent.trim() : cell.textContent.trim();
                } else if (cellIndex === 2) {
                    return getCellText(cell);
                } else {
                    return cell.textContent.trim();
                }
            })
        );
    
        return { moduleName, headers, data };
        }
        
        // Export single module
        function exportModule(tableId, format) {
            const tableData = getTableData(tableId, false);
            const filename = tableData.moduleName + '-Report';
            exportData([tableData], filename, format);
        }
        
        // Export selected from single module
        function exportModuleSelected(tableId, format) {
            const tableData = getTableData(tableId, true);
            if (tableData.data.length === 0) {
                alert('No rows selected');
                return;
            }
            const filename = tableData.moduleName + '-Selected-Report';
            exportData([tableData], filename, format);
        }
        
        // Export all modules
        function exportAll(format) {
            const tables = document.querySelectorAll('.module-content table');
            const allModuleData = [];
            
            tables.forEach(table => {
                const tableData = getTableData(table.id, false);
                if (tableData.data.length > 0) {
                    allModuleData.push(tableData);
                }
            });
            
            if (allModuleData.length === 0) {
                alert('No data to export');
                return;
            }
            
            exportData(allModuleData, 'Full-Security-Audit-Report', format);
        }
        
        // Export selected from all modules
        function exportSelected(format) {
            const tables = document.querySelectorAll('.module-content table');
            const allModuleData = [];
            
            tables.forEach(table => {
                const tableData = getTableData(table.id, true);
                if (tableData.data.length > 0) {
                    allModuleData.push(tableData);
                }
            });
            
            if (allModuleData.length === 0) {
                alert('No rows selected');
                return;
            }
            
            exportData(allModuleData, 'Selected-Security-Audit-Report', format);
        }
        
        // Main export function
        function exportData(moduleDataArray, filename, format) {
            switch(format) {
                case 'csv':
                    exportToCSV(moduleDataArray, filename + '.csv');
                    break;
                case 'excel':
                    exportToExcel(moduleDataArray, filename + '.xls');
                    break;
                case 'json':
                    exportToJSON(moduleDataArray, filename + '.json');
                    break;
                case 'xml':
                    exportToXML(moduleDataArray, filename + '.xml');
                    break;
                case 'txt':
                    exportToTXT(moduleDataArray, filename + '.txt');
                    break;
            }
        }
        
        // CSV Export - separate section per module
        function exportToCSV(moduleDataArray, filename) {
            let csv = '';
            
            moduleDataArray.forEach((moduleData, index) => {
                if (index > 0) csv += '\r\n\r\n';
        
                csv += '=== ' + moduleData.moduleName + ' ===\r\n';
                csv += moduleData.headers.map(h => '"' + h.replace(/"/g, '""') + '"').join(',') + '\r\n';
        
                moduleData.data.forEach(row => {
                    csv += row.map(cell => '"' + cell.replace(/"/g, '""').replace(/\r?\n/g, '\r\n') + '"').join(',') + '\r\n';
                });
            });
            
            downloadFile(csv, filename, 'text/csv;charset=utf-8;');
        }
        
        // Excel Export - separate sheet per module
        function exportToExcel(moduleDataArray, filename) {
            let html = '<html>\n<head><meta charset="utf-8"></head>\n<body>\n';
    
            moduleDataArray.forEach((moduleData, index) => {
                html += '<table>\n';
                html += '<tr><td colspan="' + moduleData.headers.length + '" style="font-weight:bold;font-size:14pt;background:#667eea;color:white;padding:10px;">' + escapeHtml(moduleData.moduleName) + '</td></tr>\n';
                html += '<tr>' + moduleData.headers.map(h => '<th style="background:#667eea;color:white;font-weight:bold;padding:8px;">' + escapeHtml(h) + '</th>').join('') + '</tr>\n';
        
            moduleData.data.forEach(row => {
                html += '<tr>' + row.map(cell => '<td style="padding:5px;border:1px solid #ddd; white-space:pre-wrap;">' + escapeHtml(cell).replace(/\n/g, '<br />') + '</td>').join('') + '</tr>\n';
            });
        
            html += '</table>\n';
            if (index < moduleDataArray.length - 1) {
                html += '<br><br>\n';
            }
        });
    
        html += '</body>\n</html>';
        html = html.replace(/\n/g, '\r\n');
        downloadFile(html, filename + '.xls', 'application/vnd.ms-excel');
    }
        
        // JSON Export
        function exportToJSON(moduleDataArray, filename) {
            const jsonData = {
                exportDate: new Date().toISOString(),
                modules: moduleDataArray.map(moduleData => ({
                    moduleName: moduleData.moduleName,
                    headers: moduleData.headers,
                    results: moduleData.data.map(row => {
                        const obj = {};
                        moduleData.headers.forEach((header, i) => {
                            obj[header] = row[i];
                        });
                        return obj;
                    })
                }))
            };
            
            const jsonString = JSON.stringify(jsonData, null, 2);
            downloadFile(jsonString, filename, 'application/json');
        }
        
        // XML Export
        function exportToXML(moduleDataArray, filename) {
            let xml = '<?xml version="1.0" encoding="UTF-8"?><events>\r\n';
    
            moduleDataArray.forEach(moduleData => {
                moduleData.data.forEach(row => {
                    xml += '  <event>\r\n';
                    xml += '    <module>' + escapeXml(moduleData.moduleName) + '</module>\r\n';
                    moduleData.headers.forEach((header, i) => {
                        const tagName = header.replace(/\s+/g, '').toLowerCase();
                        xml += '    <' + tagName + '>' + escapeXml(row[i]).replace(/\r?\n/g, '&#10;') + '</' + tagName + '>\r\n';
                    });
                    xml += '  </event>\r\n';
                });
            });
    
            xml += '</events>';
    
            downloadFile(xml, filename + '.xml', 'application/xml');
        }
        
        // TXT Export
        function exportToTXT(moduleDataArray, filename) {
            let txt = 'WINDOWS SECURITY AUDIT REPORT\r\n';
            txt += '================================\r\n';
            txt += 'Export Date: ' + new Date().toLocaleString() + '\r\n\r\n';
            
            moduleDataArray.forEach((moduleData, index) => {
                if (index > 0) txt += '\r\n\r\n';
                
                txt += '='.repeat(60) + '\r\n';
                txt += 'MODULE: ' + moduleData.moduleName + '\r\n';
                txt += '='.repeat(60) + '\r\n\r\n';
                
                const colWidths = moduleData.headers.map((h, i) => {
                    const processedData = moduleData.data.map(row => row[i].replace(/\r?\n/g, ' | ').length);
                    const maxDataWidth = Math.max(...processedData);
                    return Math.max(h.length, maxDataWidth, 10);
                });
                
                txt += moduleData.headers.map((h, i) => h.padEnd(colWidths[i])).join(' | ') + '\r\n';
                txt += colWidths.map(w => '-'.repeat(w)).join('-+-') + '\r\n';
                
                moduleData.data.forEach(row => {
                    const processedRow = row.map(cell => cell.replace(/\r?\n/g, ' | '));
                    txt += processedRow.map((cell, i) => cell.padEnd(colWidths[i])).join(' | ') + '\r\n';
                });
            });
            
            downloadFile(txt, filename, 'text/plain');
        }
        
        // Utility functions
        function downloadFile(content, filename, mimeType) {
            const element = document.createElement('a');
            element.setAttribute('href', 'data:' + mimeType + ';charset=utf-8,' + encodeURIComponent(content));
            element.setAttribute('download', filename);
            element.style.display = 'none';
            document.body.appendChild(element);
            element.click();
            document.body.removeChild(element);
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function escapeXml(text) {
            return text
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&apos;');
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('exportModal');
            if (event.target === modal) {
                closeExportModal();
            }
        }
    </script>
</body>
</html>
"@
    return $html
}

function Export-Results {
    param([array]$AllResults, [hashtable]$ExecutionInfo, [string]$Format, [string]$Path)
    if ([string]::IsNullOrEmpty($Path)) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $extension = switch ($Format) { "HTML" { "html" } "CSV" { "csv" } "JSON" { "json" } default { "txt" } }
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
            @{ ExecutionInfo = $ExecutionInfo; Results = $AllResults } | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
            Write-Host "`n[+] JSON report saved to: $Path" -ForegroundColor Green
        }
        "Console" { Write-Host "`n[+] Console output complete" -ForegroundColor Green }
    }
    return $Path
}

# ============================================================================
# Main Execution
# ============================================================================
function Start-SecurityAudit {
    $startTime = Get-Date
    Show-Banner
    if (-not (Test-Prerequisites)) { return }
    $modulesToRun = if ($Modules -contains "All") { @("Core", "CIS", "MS", "NIST", "STIG", "NSA", "CISA") } else { $Modules }
    Write-Host "`n[*] Modules to execute: $($modulesToRun -join ', ')" -ForegroundColor Cyan
    $missingModules = @()
    foreach ($module in $modulesToRun) {
        if (-not (Test-ModuleExists -ModuleName $module)) { $missingModules += $module }
    }
	
	# Verify all modules exist
    if ($missingModules.Count -gt 0) {
        Write-Host "`n[!] WARNING: Missing modules: $($missingModules -join ', ')" -ForegroundColor Yellow
        $modulesToRun = $modulesToRun | Where-Object { $_ -notin $missingModules }
        if ($modulesToRun.Count -eq 0) { Write-Host "[!] No modules available" -ForegroundColor Red; return }
    }
    $sharedData = @{
        ComputerName = $env:COMPUTERNAME
        OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
        ScanDate = Get-Date
        IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ScriptPath = $script:ScriptPath
        RemediateIssues = $RemediateIssues.IsPresent
    }
    $allResults = @()
    $successfulModules = @()
    foreach ($module in $modulesToRun) {
        try {
            $moduleResults = Invoke-SecurityModule -ModuleName $module -SharedData $sharedData
            if ($moduleResults -and $moduleResults.Count -gt 0) {
                $allResults += $moduleResults
                $successfulModules += $module
            }
        }
        catch { Write-Host "[!] Failed to execute module ${module}: $_" -ForegroundColor Red }
    }
    if ($allResults.Count -eq 0) { Write-Host "`n[!] No results generated" -ForegroundColor Red; return }
    $endTime = Get-Date
    $duration = $endTime - $startTime
	
	# Calculate accurate statistics using validated results
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
	
	# Display summary with validation statistics
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
    if ($script:StatisticsLog.NormalizedResults -gt 0) {
        Write-Host "`nValidation: $($script:StatisticsLog.NormalizedResults) results normalized" -ForegroundColor Yellow
    }
    Write-Host "========================================================================================================`n" -ForegroundColor Cyan
    if ($RemediateIssues) { Invoke-Remediation -Results $allResults }
    if ($OutputFormat -ne "Console") {
        $outputPath = Export-Results -AllResults $allResults -ExecutionInfo $executionInfo -Format $OutputFormat -Path $OutputPath
        if ($OutputFormat -eq "HTML" -and (Test-Path $outputPath)) {
            Write-Host "[*] Opening report in browser..." -ForegroundColor Cyan
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
    Write-Host "`n[!] Fatal error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "`nStack Trace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace -ForegroundColor Yellow
}
