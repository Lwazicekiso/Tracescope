# Tracescope Tool

## Table of Contents
1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Dependencies](#dependencies)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Scan Modes](#scan-modes)
7. [Module Descriptions](#module-descriptions)
8. [Example Scenarios](#example-scenarios)
9. [When to Use](#when-to-use)
10. [Contributing](#contributing)
11. [License](#license)

---

## Project Overview

**Tracescope Tool** is a Python-based, modular reconnaissance framework designed for both **internal** and **external** network assessments. It automates host discovery, port/service enumeration, OS fingerprinting, vulnerability scanning, DNS and WHOIS lookups, web directory brute-forcing, and CVE vulnerability searches, producing structured JSON and human-readable TXT reports.

By integrating proven open‑source utilities and Python libraries, Tracescope Tool provides a comprehensive solution for pen testers, red teams, and network administrators to rapidly gather insights about target environments with multiple scanning strategies from stealth to comprehensive assessment.

---

## Features

### Core Reconnaissance Capabilities
- **Interface & Subnet Auto-Detection**
  - Lists available network interfaces and lets you choose, then auto-calculates `/24` subnet for internal scans.
- **Concurrent Host & Port Scanning**
  - Uses Nmap (via `python-nmap`) in parallel threads to scan large subnets quickly.
- **Service & Version Enumeration**
  - Detects running services and versions via `-sV` Nmap flag with enhanced parsing.
- **OS Fingerprinting**
  - Leverages Nmap OS detection (`-O`) to guess host operating systems with accuracy ratings.

### Advanced Scanning Modes
- **Stealth Mode**
  - Evasive scanning techniques using SYN stealth scans with timing delays to avoid detection.
- **Vulnerability Scanning**
  - Integrated NSE vulnerability scripts to identify known security issues and CVEs.
- **Comprehensive Assessment**
  - Full-spectrum scanning combining all techniques for maximum information gathering.
- **Custom Scan Options**
  - Flexible argument support for advanced users and specific scanning requirements.

### Information Gathering & Analysis
- **DNS & WHOIS Lookups**
  - Fetches A, MX, NS records (`dnspython`) and WHOIS metadata (`python-whois`).
- **Web Directory Enumeration**
  - Integrates Gobuster wordlists to brute‑force common paths on web servers.
- **Enhanced CVE Lookup**
  - Queries the NVD API for known vulnerabilities matching discovered service versions.
- **Vulnerability Detection**
  - Built-in NSE script parsing for immediate vulnerability identification.
- **MAC Address & Vendor Detection**
  - Hardware identification and vendor mapping for network asset inventory.

### Utility & Reporting
- **Netcat Utilities**
  - Banner grabbing and raw TCP interactions via custom wrappers.
- **Structured Reporting**
  - Outputs both JSON and plain‑text reports with timestamps in `reports/`.
- **Enhanced Host Information**
  - Detailed port states, service confidence levels, CPE identifiers, and hostname resolution.
- **Modular & Extensible**
  - Well-organized codebase (`modules/`, `utils/`) for easy extension and customization.

---

## Dependencies

- **System Tools**
  - [Nmap](https://nmap.org/) (`apt install nmap`)
  - [Gobuster](https://github.com/OJ/gobuster) (`apt install gobuster`)
- **Python Packages** (see `requirements.txt`)
  - `python-nmap` (Nmap wrapper)
  - `psutil` (interface enumeration)
  - `dnspython` (DNS queries)
  - `python-whois` (WHOIS lookups)
  - `requests` (HTTP requests for CVE API)
  - `python3-nmap` (alternative Nmap wrapper — optional)

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Lwazicekiso/Tracescope.git
   cd Tracescope
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Ensure system tools are installed**:
   ```bash
   sudo apt update
   sudo apt install nmap gobuster netcat
   ```

---

## Usage

Run the main script to launch an interactive menu:
```bash
python3 main.py
```

You will see options:
```
[1] Internal Scan
[2] External Scan
```

### Scan Types
- **Internal Scan**: Automatically chooses an interface, discovers your `/24` subnet, runs Nmap scans in parallel, and saves `reports/internal_<IP>.json/.txt`.
- **External Scan**: Prompts for a domain or IP, performs WHOIS, DNS, Nmap, Gobuster (optional), CVE lookup, and saves `reports/external_<target>.json/.txt`.
- **Stealth Internal Scan**: Uses evasive techniques for internal reconnaissance to avoid detection systems.
- **Vulnerability Scan**: Focuses specifically on finding security vulnerabilities using NSE scripts.

### Command‑Line Flags
Alternatively, you can pass flags directly:
```bash
# Standard scans
python3 main.py --internal-scan
python3 main.py --external-scan example.com --wordlist wordlists/gobuster/common.txt

```

---

## Scan Modes

Tracescope Tool offers multiple scanning strategies to suit different scenarios:

### Default Mode
- **Purpose**: Standard reconnaissance
- **Technique**: Service detection and OS fingerprinting  
- **Speed**: Moderate
- **Stealth**: Low
- **Use Case**: General purpose scanning

### Stealth Mode
- **Purpose**: Evasive reconnaissance
- **Technique**: SYN stealth scans with timing delays
- **Speed**: Slow
- **Stealth**: High
- **Use Case**: Avoiding detection systems, IDS/IPS evasion

### Aggressive Mode  
- **Purpose**: Maximum information gathering
- **Technique**: All detection methods with fast timing
- **Speed**: Fast
- **Stealth**: Low
- **Use Case**: Internal networks, time-critical assessments

### Vulnerability Scan Mode
- **Purpose**: Security vulnerability identification
- **Technique**: NSE vulnerability scripts and CVE matching
- **Speed**: Moderate
- **Stealth**: Low
- **Use Case**: Security assessments, compliance checking

### Comprehensive Mode
- **Purpose**: Complete network assessment
- **Technique**: All available scripts and detection methods
- **Speed**: Slow
- **Stealth**: Low
- **Use Case**: Thorough security audits, detailed reconnaissance

---

## Module Descriptions

```
modules/
├── cve_lookup.py       # Query NVD API for CVEs by service/version
├── dns_enum.py         # DNS enumeration via dig/nslookup wrappers
├── external_scan.py    # Orchestrates WHOIS, DNS, Nmap, Gobuster, CVE
├── internal_scan.py    # Interface selection, subnet detection, Nmap scan
├── netcat_utils.py     # Raw TCP interactions & banner grabbing
├── nmap_scanner.py     # Enhanced Nmap wrapper with multiple scan modes
└── web_enum.py         # Gobuster integration for web dir brute-forcing
```

### Enhanced nmap_scanner.py Features
- **Multiple Scan Modes**: Default, stealth, aggressive, vulnerability, and comprehensive scanning
- **Vulnerability Detection**: Integrated NSE vulnerability script parsing
- **Enhanced Port Information**: State, confidence, CPE identifiers, and service details
- **OS Detection**: Detailed operating system fingerprinting with accuracy scores
- **MAC Address Detection**: Hardware identification and vendor mapping
- **Host Script Results**: Parsing of host-level NSE script outputs
- **Flexible Arguments**: Support for custom Nmap arguments and scan configurations

```
utils/
├── concurrency.py      # ThreadPoolExecutor wrappers for parallel tasks
├── config.py           # Default flags and paths for external tools
├── ip_utils.py         # List interfaces & detect subnet
└── output_utils.py     # Timestamped status & JSON/TXT report saving
```

```
wordlists/
└── gobuster/common.txt # Sample web directory wordlist

reports/               # Generated JSON and TXT scan reports
```

---

## Example Scenarios

### 1. Quick Internal Audit
```bash
python3 main.py --internal-scan
# Review reports/internal_<IP>.json and .txt
```

### 2. Stealth Internal Reconnaissance
```bash
python3 main.py --stealth-scan 192.168.1.0/24
# Low-profile scanning to avoid detection
```

### 3. External Vulnerability Assessment
```bash
python3 main.py --vuln-scan example.com
# Focus on finding security vulnerabilities
```

### 4. Comprehensive Security Audit
```bash
python3 main.py --comprehensive-scan target-network.com
# Complete assessment with all available techniques
```

### 5. Custom Targeted Scan
```bash
python3 main.py --custom-scan 10.0.0.100 --nmap-args "-p 1-1000 -sV -sC --script exploit"
# Advanced users with specific requirements
```

### 6. Web Directory Fuzzing with Vulnerability Check
```bash
python3 main.py --external-scan example.com --wordlist wordlists/gobuster/big.txt --vuln-check
```

---

## Advanced Features

### Vulnerability Integration
- **NSE Script Parsing**: Automatically extracts vulnerability information from Nmap NSE scripts
- **CVE Correlation**: Matches discovered services with known CVE entries
- **Risk Assessment**: Provides context for identified vulnerabilities
- **Detailed Reporting**: Comprehensive vulnerability documentation in reports

### Enhanced Reconnaissance
- **Service Fingerprinting**: Detailed service version and configuration detection
- **Banner Grabbing**: Application-layer information gathering
- **Certificate Analysis**: SSL/TLS certificate inspection for web services
- **Network Mapping**: Topology discovery and network relationship mapping

### Operational Security
- **Stealth Techniques**: Multiple evasion methods for sensitive environments
- **Timing Controls**: Configurable scan delays and timing templates  
- **Detection Avoidance**: Fragmentation and decoy scanning options
- **Logging**: Detailed operation logs for audit trails

---

## When to Use

### Security Assessments
- **Penetration Testing**: Rapidly gather host/service details across multiple scan modes
- **Vulnerability Assessments**: Identify security weaknesses with integrated CVE matching
- **Red Team Exercises**: Automate initial network mapping with stealth capabilities
- **Compliance Audits**: Document security posture and exposed services

### Network Operations  
- **IT Audits**: Comprehensive network inventory and service documentation
- **Asset Discovery**: Identify and catalog network-connected devices
- **DevOps**: Validate exposed services and configurations before deployment
- **Incident Response**: Quick network assessment during security incidents

### Research & Development
- **Security Research**: Test detection capabilities and evasion techniques
- **Tool Development**: Modular framework for custom reconnaissance tools
- **Training**: Educational platform for network security concepts
- **Automation**: Integration with larger security automation workflows

---

## Contributing

Contributions, issues, and feature requests are welcome! Areas of particular interest:

- **New Scan Modes**: Additional reconnaissance techniques and evasion methods
- **Enhanced Parsing**: Improved output parsing for new tools and techniques  
- **Reporting Features**: Enhanced visualization and analysis capabilities
- **Performance Optimization**: Faster scanning and better resource utilization
- **Detection Evasion**: Advanced techniques for avoiding security controls

Please open a GitHub issue or submit a pull request with your improvements.

---

## License

This project is licensed under the **Apache-2.0 license**. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This tool is intended for authorized security testing and network administration purposes only. Users are responsible for complying with applicable laws and regulations. Always obtain proper authorization before scanning networks or systems you do not own or have explicit permission to test.
