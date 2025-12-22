# Windows Security Audit Tool v2.0 - Modular Architecture

Comprehensive security audit system for Windows 10/11 with framework-specific modules supporting CIS, NIST, STIG, and Microsoft Security Baselines.

## 🏗️ Modular Architecture

**Main Components:**
- `Windows-Security-Audit.ps1` - Orchestrator that loads modules and aggregates results
- `Module-Core.ps1` - Essential security checks (always runs) - 30+ checks
- `Module-CIS.ps1` - CIS Benchmark specific checks - 40+ checks
- `Module-NIST.ps1` - NIST 800-53 controls - 25+ checks  
- `Module-STIG.ps1` - DISA STIG requirements - 20+ checks
- `Module-MS.ps1` - Microsoft Security Baselines - 25+ checks

**Total: 160+ Security Checks**

## 🚀 Quick Start

```powershell
# Run all frameworks with HTML report
.\Windows-Security-Audit.ps1 -Framework ALL -AutoSave -Format HTML

# Run specific framework
.\Windows-Security-Audit.ps1 -Framework CIS -AutoSave

# Remediate critical issues
.\Windows-Security-Audit.ps1 -Severity Critical -Remediate

# Run CIS and NIST only
.\Windows-Security-Audit.ps1 -Framework CIS,NIST -AutoSave -Format JSON
```

## 📋 What Gets Checked

### Core Module (Essential - Always Runs)
✅ Windows Defender (10 checks) - Real-time, Behavior, Cloud, Signatures, ASR  
✅ Windows Firewall (6 checks) - All profiles, inbound rules  
✅ UAC (3 checks) - Admin approval, secure desktop, elevation prompts  
✅ Password Policy (6 checks) - Length, complexity, history, age  
✅ Account Lockout (3 checks) - Threshold, duration, window  
✅ Windows Update (2 checks) - Auto-update, pending updates  
✅ SMB (2 checks) - SMBv1 disabled, signing required  
✅ PowerShell (2 checks) - Execution policy, v2 disabled  
✅ RDP (3 checks) - Status, NLA, port  
✅ Credentials (2 checks) - LSA Protection, WDigest disabled  
✅ Network (1 check) - LLMNR disabled  
✅ AutoRun (1 check) - Disabled for all drives

### CIS Module
✅ Advanced Audit Policies (30+ subcategories)  
✅ User Rights Assignments  
✅ Security Options  
✅ Anonymous Enumeration Controls  
✅ IP Source Routing  
✅ DNS Client Settings  
✅ Credential UI  
✅ Event Log Sizes  
✅ Windows Installer Policies  
✅ PowerShell Script Block Logging

### NIST Module
✅ Access Control (AC Family)  
✅ Session Management (AC-11)  
✅ Patch Management (SI-2)  
✅ Encryption at Rest (SC-28 - BitLocker)  
✅ Audit Log Size (AU-4)  
✅ Service Management (CM-7)

### STIG Module
✅ NTFS File System Requirements  
✅ Command Line Auditing  
✅ Anonymous SID Translation  
✅ LM Hash Storage  
✅ Virtualization-Based Security  
✅ Credential Guard  
✅ Telnet/Simple TCP Disabled

### MS Baseline Module
✅ Attack Surface Reduction Rules  
✅ Controlled Folder Access  
✅ Network Protection  
✅ Exploit Protection  
✅ SmartScreen  
✅ HVCI  
✅ Secure Boot  
✅ AppLocker

## 📊 Parameters

| Parameter | Values | Description |
|-----------|--------|-------------|
| `-Framework` | ALL, CIS, NIST, STIG, MS | Which frameworks to audit |
| `-Remediate` | Switch | Enable interactive fixes |
| `-AutoSave` | Switch | Save report automatically |
| `-Format` | Text, HTML, CSV, JSON | Output format |
| `-Severity` | ALL, Critical, High, Medium, Low | Filter by severity |
| `-ModulePath` | Path | Custom module directory |

## 💡 Example Workflows

### Initial Assessment
```powershell
# Complete audit with HTML report
.\Windows-Security-Audit.ps1 -Framework ALL -AutoSave -Format HTML
# Review report: Desktop\SecurityAudit_HOSTNAME_TIMESTAMP.html
```

### Fix Critical Issues
```powershell
# Interactive remediation for critical findings
.\Windows-Security-Audit.ps1 -Severity Critical -Remediate
```

### Compliance Check
```powershell
# CIS Benchmark compliance audit
.\Windows-Security-Audit.ps1 -Framework CIS -AutoSave -Format JSON
```

### Re-verification
```powershell
# Verify fixes were applied
.\Windows-Security-Audit.ps1 -Framework ALL -AutoSave
```

## 🔧 Extending the Tool

### Add Custom Module

1. Create `Module-Custom.ps1`:
```powershell
function Invoke-CustomChecks {
    param([string]$Severity = 'ALL')
    $results = @{Passed=@(); Failed=@(); Warnings=@(); Info=@()}
    # Add your checks here
    return $results
}
```

2. Place in same directory as main script
3. Run: `.\Windows-Security-Audit.ps1 -Framework Custom`

### Module Structure
Each module must:
- Be named `Module-{Name}.ps1`
- Contain `Invoke-{Name}Checks` function
- Return hashtable with Passed/Failed/Warnings/Info arrays
- Use consistent result object structure

## ⚠️ Important Notes

**Before Running:**
1. Create system restore point
2. Test in non-production environment first
3. Review findings before applying fixes
4. Some fixes require restart

**Remediation:**
- Interactive prompts for each fix
- Shows command before executing
- Manual instructions for items requiring intervention
- Organized by severity (Critical → High → Medium → Low)

## 📈 Output Examples

### Console Output
```
[PASS] Windows Defender - Real-time protection enabled
       Current: Enabled | Expected: Enabled
       Frameworks: CIS 18.9.45.4.1 | NIST SI-3 | STIG V-220744

[FAIL] SMB - SMBv1 protocol ENABLED
       Current: Enabled | Expected: Disabled
       Frameworks: CIS 18.3.1 | NIST CM-7 | STIG V-220748
       Remediation: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

### HTML Report
- Color-coded results table
- Sortable by category/severity
- Framework mappings displayed
- Remediation commands included
- Summary statistics

## 🛡️ Security Best Practices Checked

**Passwords:** 14+ chars, complexity, history 24, max age 60 days  
**Lockout:** 5-10 attempts, 15+ min duration  
**Defender:** Real-time ON, Cloud Advanced, Behavior ON  
**Firewall:** All profiles enabled, inbound blocked  
**Network:** SMBv1 OFF, SMB signing ON, LLMNR OFF  
**Credentials:** LSA Protection ON, WDigest OFF, Cred Guard ON  
**Updates:** Auto-update enabled, no critical pending  
**PowerShell:** RemoteSigned policy, v2 disabled  
**UAC:** Enabled, secure desktop, admin approval

## 📚 Framework References

- **CIS:** [Windows 10/11 Benchmark v2.0.0](https://www.cisecurity.org/cis-benchmarks/)
- **NIST:** [SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- **STIG:** [Windows 10/11 V2R8](https://public.cyber.mil/stigs/)
- **MS:** [Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)

## 📞 Support

**System Requirements:**
- Windows 10 or Windows 11
- PowerShell 5.1 or higher
- Administrator privileges

**Troubleshooting:**
- Ensure all module files are in same directory
- Check PowerShell execution policy
- Verify Administrator privileges
- Review error messages in console output

---
**Version:** 2.0 - Modular Architecture  
**Last Updated:** 22 December 2025  
**License:** Security Assessment Use
