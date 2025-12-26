# Windows Security Audit Script

A comprehensive PowerShell-based security compliance auditing tool for Windows systems. This project evaluates Windows configurations against multiple industry-standard security frameworks including DISA STIGs, NIST 800-53, CIS Benchmarks, NSA Cybersecurity guidance, CISA Cybersecurity Performance Goals, and Microsoft Security Baselines.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20%7C%20Server%202016%2B-lightgrey.svg)](https://www.microsoft.com/windows)

## 🎯 Overview

The Windows Security Audit Script performs **550+ automated security checks** across seven compliance modules, helping organizations assess their Windows systems against multiple security frameworks simultaneously. The tool generates comprehensive reports in multiple formats (HTML, JSON, CSV, and console output) for analysis, compliance reporting, and remediation planning.

### Key Features

- ✅ **Multi-Framework Coverage** - Simultaneously audits against 7 major security frameworks
- ✅ **550+ Security Checks** - Comprehensive evaluation of system configuration
- ✅ **Multiple Output Formats** - HTML, JSON, CSV, and colored console output
- ✅ **Modular Architecture** - Easy to extend and customize
- ✅ **Detailed Remediation** - Actionable guidance for each finding
- ✅ **No External Dependencies** - Pure PowerShell implementation
- ✅ **Categorized Results** - Pass/Fail/Warning/Info/Error classifications
- ✅ **Executive Summary** - High-level compliance overview with statistics

## 📋 Supported Frameworks

| Module | Framework | Checks | Severity Levels |
|--------|-----------|--------|----------------|
| **STIG** | DISA Security Technical Implementation Guide | 90+ | CAT I/II/III |
| **NIST** | NIST 800-53 Rev 5 & Cybersecurity Framework | 50+ | Control Families |
| **CIS** | CIS Microsoft Windows Benchmarks | 100+ | Scored/Not Scored |
| **NSA** | NSA Cybersecurity Information Sheets | 60+ | Best Practices |
| **CISA** | CISA Cybersecurity Performance Goals | 80+ | Critical Controls |
| **MS** | Microsoft Security Baselines (SCT) | 80+ | Recommendations |
| **Core** | Foundational Windows Security Baseline | 40+ | Essential Checks |

## 🚀 Quick Start

### Prerequisites

- **Operating System**: Windows 10/11 or Windows Server 2016/2019/2022
- **PowerShell**: Version 5.1 or later (included in modern Windows)
- **Execution Policy**: Must allow script execution (see below)
- **Privileges**: Administrator rights required for comprehensive auditing

### Installation

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/Sandler73/Windows-Security-Audit-Script.git
   cd Windows-Security-Audit-Script
   ```

2. **Set execution policy (if needed):**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Basic Usage

**Run all modules with default settings:**
```powershell
.\Windows-Security-Audit-Script.ps1
```

**Run specific modules:**
```powershell
.\Windows-Security-Audit-Script.ps1 -Modules STIG,NIST,CIS
```

**Generate only HTML report:**
```powershell
.\Windows-Security-Audit-Script.ps1 -OutputFormats HTML
```

**Specify custom output directory:**
```powershell
.\Windows-Security-Audit-Script.ps1 -OutputPath "C:\SecurityAudits"
```

## 📊 Output Formats

The script generates reports in multiple formats:

### 1. **HTML Report** (Default: `SecurityAudit_Report_YYYYMMDD_HHMMSS.html`)
- Executive summary dashboard
- Module-by-module results with color coding
- Interactive filtering and search
- Detailed findings with remediation steps
- Export-friendly formatting

### 2. **JSON Report** (Default: `SecurityAudit_Report_YYYYMMDD_HHMMSS.json`)
- Structured data for automation and integration
- Includes system information and metadata
- Parseable by SIEM and analysis tools
- API-friendly format

### 3. **CSV Report** (Default: `SecurityAudit_Report_YYYYMMDD_HHMMSS.csv`)
- Spreadsheet-compatible format
- Easy filtering and sorting in Excel
- Suitable for tracking remediation progress
- Dashboard and pivot table creation

### 4. **Console Output**
- Real-time progress display
- Color-coded status indicators
- Module-by-module summaries
- Final statistics and recommendations

## 🏗️ Architecture

```
Windows-Security-Audit-Script/
├── Windows-Security-Audit-Script.ps1    # Main orchestrator
├── Modules/
│   ├── Module-Core.ps1                  # Foundational security checks
│   ├── Module-STIG.ps1                  # DISA STIG compliance
│   ├── Module-NIST.ps1                  # NIST 800-53 controls
│   ├── Module-CIS.ps1                   # CIS Benchmarks
│   ├── Module-NSA.ps1                   # NSA security guidance
│   ├── Module-CISA.ps1                  # CISA performance goals
│   └── Module-MS.ps1                    # Microsoft baselines
├── README.md                             # This file
└── LICENSE                               # MIT License
```

### Module Design

Each module follows a consistent structure:
- **Independent execution** - Can run standalone or via orchestrator
- **Standardized output** - Uniform result format across modules
- **Error handling** - Graceful degradation on check failures
- **Detailed remediation** - PowerShell commands or GPO guidance
- **Framework alignment** - Mapped to specific control IDs/requirements

## 🔍 What Gets Audited?

### Security Domains Covered

- **Access Control** - Account policies, user rights, privilege management
- **Audit & Accountability** - Event logging, audit policies, log retention
- **Authentication** - Password policies, multi-factor authentication, credential protection
- **System Hardening** - UAC, Secure Boot, service configuration, least privilege
- **Network Security** - Firewall rules, SMB security, protocol configuration
- **Data Protection** - Encryption (BitLocker), data at rest, transmission security
- **Malware Defense** - Windows Defender, real-time protection, signature updates
- **Application Control** - AppLocker, WDAC, software restriction policies
- **Update Management** - Windows Update configuration, patch status
- **Incident Response** - System monitoring, logging capabilities, recovery options

### Example Checks

- ✅ Password complexity and length requirements
- ✅ Account lockout policies
- ✅ Windows Firewall configuration across all profiles
- ✅ SMBv1 protocol status (should be disabled)
- ✅ BitLocker encryption status
- ✅ Windows Defender real-time protection
- ✅ Audit policy configuration (18+ subcategories)
- ✅ User Account Control (UAC) settings
- ✅ Remote Desktop security (NLA, encryption)
- ✅ PowerShell logging and security features
- ✅ Service configuration (unnecessary services)
- ✅ Event log sizes and retention
- ✅ Local administrator enumeration
- ✅ Guest account status
- ✅ Credential protection mechanisms

## 📖 Documentation

Comprehensive documentation is available in the [Wiki](https://github.com/Sandler73/Windows-Security-Audit-Script/wiki):

- **[Quick Start Guide](../../wiki/Quick-Start-Guide)** - Get running in 5 minutes
- **[Usage Guide](../../wiki/Usage-Guide)** - Detailed usage instructions and examples
- **[Framework Reference](../../wiki/Framework-Reference)** - Security framework details and mappings
- **[Module Documentation](../../wiki/Module-Documentation)** - Individual module specifications
- **[Output Reference](../../wiki/Output-Reference)** - Understanding report formats
- **[Troubleshooting](../../wiki/Troubleshooting)** - Common issues and solutions
- **[Development Guide](../../wiki/Development-Guide)** - Contributing and extending modules

## 🛠️ Advanced Usage

### Command-Line Parameters

```powershell
.\Windows-Security-Audit-Script.ps1 
    [-Modules <String[]>]           # Modules to run (default: all)
    [-OutputPath <String>]          # Output directory (default: .\Reports)
    [-OutputFormats <String[]>]     # Output formats (default: HTML,JSON,CSV)
    [-NoConsoleOutput]              # Suppress console output
    [-Verbose]                      # Detailed progress information
```

### Examples

**Run only CAT I (critical) STIG checks:**
```powershell
.\Windows-Security-Audit-Script.ps1 -Modules STIG
# Then filter results by "CAT I" in the report
```

**Generate JSON only for SIEM integration:**
```powershell
.\Windows-Security-Audit-Script.ps1 -OutputFormats JSON -NoConsoleOutput
```

**Compliance baseline for multiple frameworks:**
```powershell
.\Windows-Security-Audit-Script.ps1 -Modules NIST,CIS,MS -OutputPath "C:\Compliance\Baseline"
```

**Quick security assessment (core checks only):**
```powershell
.\Windows-Security-Audit-Script.ps1 -Modules Core
```

## 🎯 Use Cases

### 1. **Compliance Auditing**
Assess Windows systems against regulatory requirements (NIST 800-53, DISA STIGs) for compliance reporting.

### 2. **Security Baseline Validation**
Verify that systems meet organizational security baselines and hardening standards.

### 3. **Vulnerability Assessment**
Identify security misconfigurations that could be exploited by attackers.

### 4. **Pre-Deployment Validation**
Audit gold images and system templates before deployment to production.

### 5. **Continuous Monitoring**
Schedule regular audits to detect configuration drift and maintain security posture.

### 6. **Incident Response**
Quickly assess system security configuration during incident investigation.

### 7. **Remediation Tracking**
Generate baseline reports, remediate findings, then re-run to verify fixes.

## ⚠️ Important Notes

### Limitations

- **Administrative Access Required** - Many checks require administrator privileges
- **Local Assessment Only** - Audits the local system, not remote systems or domains
- **Point-in-Time** - Results represent configuration at execution time
- **Read-Only** - Script does not make any configuration changes
- **Performance Impact** - Comprehensive audits may take 2-5 minutes to complete

### Security Considerations

- ✅ Script is **read-only** and makes no system changes
- ✅ No data is transmitted externally
- ✅ Reports may contain sensitive system information - secure appropriately
- ✅ Review script contents before execution (security best practice)
- ✅ Audit logs may be generated in Windows Event Logs

### Disclaimer

This tool is provided for **security assessment and compliance auditing purposes**. Results should be reviewed by qualified security professionals. The tool identifies potential security issues but does not guarantee comprehensive security coverage. Always test in non-production environments first.

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guidelines](https://github.com/Sandler73/Windows-Security-Audit-Script/blob/main/CONTRIBUTING.md) for details.

### Ways to Contribute

- 🐛 Report bugs and issues
- 💡 Suggest new features or checks
- 📝 Improve documentation
- 🔧 Submit bug fixes
- ✨ Add new security modules or frameworks
- 🧪 Test on different Windows versions

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Test thoroughly on multiple Windows versions
5. Commit your changes (`git commit -m 'Add AmazingFeature'`)
6. Push to the branch (`git push origin feature/AmazingFeature`)
7. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/Sandler73/Windows-Security-Audit-Script/blob/main/LICENSE) file for details.

## 🙏 Acknowledgments

This project builds upon the work of various security organizations and frameworks:

- **DISA** - Defense Information Systems Agency STIGs
- **NIST** - National Institute of Standards and Technology (800-53, CSF)
- **CIS** - Center for Internet Security Benchmarks
- **NSA** - National Security Agency Cybersecurity Guidance
- **CISA** - Cybersecurity and Infrastructure Security Agency
- **Microsoft** - Security Compliance Toolkit and Baselines

See the [Framework Reference](https://github.com/Sandler73/Windows-Security-Audit-Script/wiki/Framework-Reference) wiki page for detailed citations and references.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Sandler73/Windows-Security-Audit-Script/issues)
- **Discussions**: [GitHub Discussions](../../discussions)
- **Wiki**: [Project Wiki](https://github.com/Sandler73/Windows-Security-Audit-Script/wiki)

## 🔄 Version History

See [CHANGELOG.md](https://github.com/Sandler73/Windows-Security-Audit-Script/blob/main/CHANGELOG.md) for detailed version history.

### Current Version: 5.0

- Complete rewrite with modular architecture
- 550+ security checks across 7 frameworks
- Multiple output formats (HTML, JSON, CSV)
- Improved error handling and logging
- Comprehensive documentation

## 📊 Statistics

- **Total Security Checks**: 550+
- **Frameworks Covered**: 7
- **Lines of Code**: ~10,000
- **Windows Versions Tested**: 10, 11, Server 2016/2019/2022
- **PowerShell Version**: 5.1+

---

**⭐ If you find this project useful, please consider giving it a star!**

**Made with ❤️ for the cybersecurity community**
