<#
.SYNOPSIS
    Windows Security Audit & Remediation Tool - Main Orchestrator v2.0
    
.DESCRIPTION
    Modular security audit system for Windows 10/11. Orchestrates framework-specific
    check modules and aggregates results. Supports CIS, NIST, STIG, and MS Baseline.
    
.PARAMETER Framework
    Security framework(s): ALL, CIS, NIST, STIG, MS, or comma-separated
    
.PARAMETER Remediate
    Enable interactive remediation mode
    
.PARAMETER AutoSave
    Automatically save report with timestamp
    
.PARAMETER Format
    Report format: Text, HTML, CSV, or JSON
    
.PARAMETER Severity
    Filter by severity: ALL, Critical, High, Medium, Low
    
.PARAMETER ModulePath
    Path to framework modules (default: script directory)

.EXAMPLE
    .\Windows-Security-Audit.ps1 -Framework CIS -AutoSave -Format HTML
    
.EXAMPLE
    .\Windows-Security-Audit.ps1 -Framework CIS,NIST -Remediate -Severity Critical

.NOTES
    Version: 2.0 - Modular Architecture
    Requires: PowerShell 5.1+, Administrator
#>

[CmdletBinding()]
param(
    [ValidateSet('ALL','CIS','NIST','STIG','MS','Core')]
    [string[]]$Framework = @('ALL'),
    [switch]$Remediate,
    [switch]$AutoSave,
    [ValidateSet('Text','HTML','CSV','JSON')]
    [string]$Format = 'Text',
    [ValidateSet('ALL','Critical','High','Medium','Low')]
    [string]$Severity = 'ALL',
    [string]$ModulePath = $PSScriptRoot
)

#Requires -RunAsAdministrator

# Initialize
$script:Version = "2.0"
$script:Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$script:Hostname = $env:COMPUTERNAME
$script:OSInfo = Get-CimInstance Win32_OperatingSystem
$script:OSBuild = $script:OSInfo.BuildNumber
$script:IsWindows11 = $script:OSBuild -ge 22000
$script:OSName = if($script:IsWindows11){"Windows 11"}else{"Windows 10"}

$script:AggregatedResults = @{Passed=@(); Failed=@(); Warnings=@(); Info=@()}
$script:RemediationActions = @()
$script:ModulesExecuted = @()
$script:TotalChecks = 0

# Output functions
function Write-Pass{param($M) Write-Host "[PASS] $M" -ForegroundColor Green}
function Write-Fail{param($M) Write-Host "[FAIL] $M" -ForegroundColor Red}
function Write-Warn{param($M) Write-Host "[WARN] $M" -ForegroundColor Yellow}
function Write-Info{param($M) Write-Host "[INFO] $M" -ForegroundColor Cyan}
function Write-Section{param($M) Write-Host "`n--- $M ---" -ForegroundColor Magenta; Write-Host ""}

function Show-Banner {
    $fwList = if($Framework -contains 'ALL'){"All Frameworks"}else{$Framework -join ", "}
    Write-Host @"

===========================================================================
       Windows Security Audit & Remediation Tool v$script:Version
                   Modular Architecture Edition
===========================================================================

Hostname:           $script:Hostname
Timestamp:          $script:Timestamp
OS:                 $script:OSName (Build $script:OSBuild)
PowerShell:         $($PSVersionTable.PSVersion)
Framework(s):       $fwList
Severity Filter:    $Severity
Module Path:        $ModulePath

"@ -ForegroundColor Cyan
}

function Get-AvailableModules {
    $modules = @()
    $moduleFiles = Get-ChildItem -Path $ModulePath -Filter "Module-*.ps1" -ErrorAction SilentlyContinue
    
    foreach($file in $moduleFiles){
        if($file.Name -match 'Module-(\w+)\.ps1'){
            $modules += @{Name=$matches[1]; Path=$file.FullName; File=$file.Name}
        }
    }
    return $modules
}

function Invoke-SecurityModule {
    param([string]$ModuleName, [string]$ModulePath, [string]$SeverityFilter='ALL')
    
    Write-Section "Loading Module: $ModuleName"
    
    try {
        . $ModulePath
        
        if(Get-Command "Invoke-${ModuleName}Checks" -ErrorAction SilentlyContinue){
            Write-Info "Executing $ModuleName security checks..."
            $moduleResults = & "Invoke-${ModuleName}Checks" -Severity $SeverityFilter
            
            if($moduleResults){
                $script:AggregatedResults.Passed += $moduleResults.Passed
                $script:AggregatedResults.Failed += $moduleResults.Failed
                $script:AggregatedResults.Warnings += $moduleResults.Warnings
                $script:AggregatedResults.Info += $moduleResults.Info
                
                foreach($item in $moduleResults.Failed){
                    if($item.Remediation){$script:RemediationActions += $item}
                }
                
                $script:TotalChecks += ($moduleResults.Passed.Count + $moduleResults.Failed.Count + 
                                       $moduleResults.Warnings.Count + $moduleResults.Info.Count)
                $script:ModulesExecuted += $ModuleName
                
                Write-Info "Module complete: $($moduleResults.Passed.Count) passed, $($moduleResults.Failed.Count) failed, $($moduleResults.Warnings.Count) warnings"
            }
        } else {
            Write-Warn "Module $ModuleName missing Invoke-${ModuleName}Checks function"
        }
    } catch {
        Write-Fail "Error executing module ${ModuleName}: $($_.Exception.Message)"
    }
}

function Start-Remediation {
    Write-Host "`n===========================================================================" -ForegroundColor Cyan
    Write-Host "                 Interactive Remediation Mode" -ForegroundColor Cyan
    Write-Host "===========================================================================`n" -ForegroundColor Cyan
    
    if($script:RemediationActions.Count -eq 0){
        Write-Host "No automated remediations available." -ForegroundColor Green
        return
    }
    
    Write-Host "Found $($script:RemediationActions.Count) issues with automated fixes.`n" -ForegroundColor Yellow
    
    $grouped = $script:RemediationActions | Group-Object Severity | Sort-Object {
        switch($_.Name){"Critical"{0}"High"{1}"Medium"{2}"Low"{3}default{4}}
    }
    
    foreach($group in $grouped){
        $color = switch($group.Name){"Critical"{"Red"}"High"{"DarkRed"}"Medium"{"Yellow"}"Low"{"DarkYellow"}default{"Gray"}}
        Write-Host "`n=== $($group.Name) Severity ($($group.Count) items) ===" -ForegroundColor $color
        
        $itemNum = 1
        foreach($item in $group.Group){
            Write-Host "`n[$itemNum/$($group.Count)] $($item.Category): $($item.Message)" -ForegroundColor Yellow
            if($item.Details){Write-Host "    Details: $($item.Details)" -ForegroundColor Gray}
            if($item.CurrentValue -ne "N/A"){
                Write-Host "    Current: $($item.CurrentValue) | Expected: $($item.ExpectedValue)" -ForegroundColor Gray
            }
            
            if($item.Remediation -match '^#'){
                Write-Host "    Manual: $($item.Remediation)`n" -ForegroundColor DarkGray
                $itemNum++
                continue
            }
            
            Write-Host "    Fix: $($item.Remediation)" -ForegroundColor White
            
            do {$response = (Read-Host "    Apply? (y/n/q)").ToLower()}
            while($response -notin @('y','n','q'))
            
            if($response -eq 'q'){Write-Host "`nCancelled." -ForegroundColor Yellow; return}
            
            if($response -eq 'y'){
                try {
                    Write-Host "    Applying..." -ForegroundColor Cyan
                    Invoke-Expression $item.Remediation
                    Write-Host "    [OK] Success`n" -ForegroundColor Green
                } catch {
                    Write-Host "    [ERROR] $($_.Exception.Message)`n" -ForegroundColor Red
                }
            } else {Write-Host "    Skipped`n" -ForegroundColor DarkGray}
            
            $itemNum++
        }
    }
    
    Write-Host "`nRemediation complete." -ForegroundColor Green
}

function Export-Report {
    param([string]$OutputFormat, [string]$OutputPath)
    
    switch($OutputFormat){
        'HTML' {
            $html = @"
<!DOCTYPE html>
<html><head><title>Security Audit Report</title>
<style>
body{font-family:'Segoe UI',Arial;margin:20px;background:#f5f5f5}
.container{max-width:1400px;margin:0 auto;background:white;padding:30px;box-shadow:0 0 10px rgba(0,0,0,0.1)}
h1{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px}
h2{color:#34495e;margin-top:30px;border-bottom:1px solid #ddd}
.summary{background:#ecf0f1;padding:20px;border-radius:5px;margin:20px 0;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px}
.summary-item{text-align:center;padding:15px;background:white;border-radius:5px}
.summary-item .value{font-size:2em;font-weight:bold}
.passed .value{color:#27ae60}
.failed .value{color:#e74c3c}
.warnings .value{color:#f39c12}
table{border-collapse:collapse;width:100%;margin:15px 0}
th,td{border:1px solid #ddd;padding:12px;text-align:left}
th{background:#3498db;color:white}
tr:nth-child(even){background:#f9f9f9}
.critical{background:#ffebee}
.high{background:#fff3e0}
code{background:#f4f4f4;padding:2px 5px;border-radius:3px;font-family:Consolas}
</style></head><body><div class="container">
<h1>Windows Security Audit Report</h1>
<p><strong>Host:</strong> $script:Hostname | <strong>OS:</strong> $script:OSName | <strong>Date:</strong> $script:Timestamp</p>
<p><strong>Frameworks:</strong> $($Framework -join ', ') | <strong>Modules:</strong> $($script:ModulesExecuted -join ', ')</p>
<div class="summary">
<div class="summary-item passed"><div class="value">$($script:AggregatedResults.Passed.Count)</div><div class="label">Passed</div></div>
<div class="summary-item failed"><div class="value">$($script:AggregatedResults.Failed.Count)</div><div class="label">Failed</div></div>
<div class="summary-item warnings"><div class="value">$($script:AggregatedResults.Warnings.Count)</div><div class="label">Warnings</div></div>
</div>
"@
            
            if($script:AggregatedResults.Failed.Count -gt 0){
                $html += "<h2>Failed Checks ($($script:AggregatedResults.Failed.Count))</h2><table><tr><th>Category</th><th>Severity</th><th>Message</th><th>Current</th><th>Expected</th><th>Remediation</th></tr>"
                foreach($item in $script:AggregatedResults.Failed | Sort-Object {switch($_.Severity){"Critical"{0}"High"{1}"Medium"{2}default{3}}}){
                    $rem = if($item.Remediation){"<code>$($item.Remediation)</code>"}else{"Manual"}
                    $rowClass = if($item.Severity -eq "Critical"){"critical"}elseif($item.Severity -eq "High"){"high"}else{""}
                    $html += "<tr class='$rowClass'><td>$($item.Category)</td><td>$($item.Severity)</td><td>$($item.Message)</td><td>$($item.CurrentValue)</td><td>$($item.ExpectedValue)</td><td style='font-size:0.9em'>$rem</td></tr>"
                }
                $html += "</table>"
            }
            
            if($script:AggregatedResults.Warnings.Count -gt 0){
                $html += "<h2>Warnings ($($script:AggregatedResults.Warnings.Count))</h2><table><tr><th>Category</th><th>Severity</th><th>Message</th><th>Current</th><th>Expected</th><th>Details</th></tr>"
                foreach($item in $script:AggregatedResults.Warnings | Sort-Object {switch($_.Severity){"Critical"{0}"High"{1}"Medium"{2}default{3}}}){
                    $html += "<tr><td>$($item.Category)</td><td>$($item.Severity)</td><td>$($item.Message)</td><td>$($item.CurrentValue)</td><td>$($item.ExpectedValue)</td><td style='font-size:0.9em'>$($item.Details)</td></tr>"
                }
                $html += "</table>"
            }
            
            if($script:AggregatedResults.Passed.Count -gt 0){
                $html += "<h2>Passed Checks ($($script:AggregatedResults.Passed.Count))</h2><table><tr><th>Category</th><th>Message</th><th>Current Value</th><th>Frameworks</th></tr>"
                foreach($item in $script:AggregatedResults.Passed | Sort-Object Category){
                    $html += "<tr><td>$($item.Category)</td><td>$($item.Message)</td><td>$($item.CurrentValue)</td><td style='font-size:0.85em'>$($item.Frameworks)</td></tr>"
                }
                $html += "</table>"
            }
            
            $html += "</div></body></html>"
            $html | Out-File -FilePath $OutputPath -Encoding UTF8
        }
        
        'JSON' {
            @{
                Metadata=@{Hostname=$script:Hostname;OS=$script:OSName;Timestamp=$script:Timestamp;Frameworks=$Framework}
                Summary=@{Passed=$script:AggregatedResults.Passed.Count;Failed=$script:AggregatedResults.Failed.Count;Warnings=$script:AggregatedResults.Warnings.Count}
                Results=$script:AggregatedResults
            } | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        }
        
        'CSV' {
            $all = @()
            $all += $script:AggregatedResults.Passed | Select-Object Status,Category,Message,CurrentValue,ExpectedValue,Severity
            $all += $script:AggregatedResults.Failed | Select-Object Status,Category,Message,CurrentValue,ExpectedValue,Severity,Remediation
            $all += $script:AggregatedResults.Warnings | Select-Object Status,Category,Message,CurrentValue,ExpectedValue,Severity
            $all | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        }
        
        Default {
            @"
===========================================================================
                  Windows Security Audit Report
===========================================================================

Host:       $script:Hostname
OS:         $script:OSName (Build $script:OSBuild)
Date:       $script:Timestamp
Frameworks: $($Framework -join ', ')
Modules:    $($script:ModulesExecuted -join ', ')

===========================================================================
SUMMARY
===========================================================================
Total:      $script:TotalChecks
Passed:     $($script:AggregatedResults.Passed.Count)
Failed:     $($script:AggregatedResults.Failed.Count)
Warnings:   $($script:AggregatedResults.Warnings.Count)

"@ + $(if($script:AggregatedResults.Failed.Count -gt 0){
"`n===========================================================================
FAILED CHECKS
===========================================================================

" + $(($script:AggregatedResults.Failed | Sort-Object {switch($_.Severity){"Critical"{0}"High"{1}"Medium"{2}default{3}}} | ForEach-Object{
"[$($_.Severity)] $($_.Category): $($_.Message)
    Current: $($_.CurrentValue) | Expected: $($_.ExpectedValue)
$(if($_.Details){"    Details: $($_.Details)"})
$(if($_.Remediation){"    Fix: $($_.Remediation)"})

"}) -join "")}) | Out-File -FilePath $OutputPath -Encoding UTF8
        }
    }
    
    Write-Host "`nReport saved: $OutputPath" -ForegroundColor Green
}

# Main execution
Show-Banner

$frameworksToRun = if($Framework -contains 'ALL'){@('CIS','NIST','STIG','MS','Core')}else{$Framework + 'Core'}

Write-Info "Discovering modules..."
$availableModules = Get-AvailableModules

if($availableModules.Count -eq 0){
    Write-Warn "No modules found in $ModulePath"
    Write-Info "Expected: Module-CIS.ps1, Module-NIST.ps1, Module-STIG.ps1, Module-MS.ps1, Module-Core.ps1"
    exit 1
}

Write-Info "Found: $($availableModules.Name -join ', ')"

foreach($fw in $frameworksToRun){
    $module = $availableModules | Where-Object{$_.Name -eq $fw} | Select-Object -First 1
    if($module){
        Invoke-SecurityModule -ModuleName $module.Name -ModulePath $module.Path -SeverityFilter $Severity
    } else {
        Write-Warn "Module '$fw' not found (expected Module-$fw.ps1)"
    }
}

# Summary
Write-Section "Audit Summary"
Write-Host "Total Checks: $script:TotalChecks" -ForegroundColor Cyan
Write-Host "Modules: $($script:ModulesExecuted -join ', ')" -ForegroundColor Cyan
Write-Host ""
Write-Host "Passed:   " -NoNewline; Write-Host $script:AggregatedResults.Passed.Count -ForegroundColor Green
Write-Host "Failed:   " -NoNewline; Write-Host $script:AggregatedResults.Failed.Count -ForegroundColor Red
Write-Host "Warnings: " -NoNewline; Write-Host $script:AggregatedResults.Warnings.Count -ForegroundColor Yellow

# Auto-save
if($AutoSave){
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $fn = "SecurityAudit_$($env:COMPUTERNAME)_$ts"
    $path = switch($Format){
        'HTML'{"$env:USERPROFILE\Desktop\$fn.html"}
        'JSON'{"$env:USERPROFILE\Desktop\$fn.json"}
        'CSV'{"$env:USERPROFILE\Desktop\$fn.csv"}
        Default{"$env:USERPROFILE\Desktop\$fn.txt"}
    }
    Export-Report -OutputFormat $Format -OutputPath $path
}

# Remediation
if($Remediate){Start-Remediation}

Write-Host "`n[OK] Complete!" -ForegroundColor Green
