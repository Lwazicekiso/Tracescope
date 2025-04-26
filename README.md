# Recon Tool

## Table of Contents
1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Dependencies](#dependencies)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Module Descriptions](#module-descriptions)
7. [Example Scenarios](#example-scenarios)
8. [When to Use](#when-to-use)
9. [Contributing](#contributing)
10. [License](#license)

---

## Project Overview

**Recon Tool** is a Python-based, modular reconnaissance framework designed for both **internal** and **external** network assessments. It automates host discovery, port/service enumeration, OS fingerprinting, DNS and WHOIS lookups, web directory brute-forcing, and CVE vulnerability searches, producing structured JSON and human-readable TXT reports.

By integrating proven open‑source utilities and Python libraries, Recon Tool provides a one‑stop solution for pen testers, red teams, and network administrators to rapidly gather insights about target environments.

---

## Features

- **Interface & Subnet Auto-Detection**
  - Lists available network interfaces and lets you choose, then auto-calculates `/24` subnet for internal scans.
- **Concurrent Host & Port Scanning**
  - Uses Nmap (via `python-nmap`) in parallel threads to scan large subnets quickly.
- **Service & Version Enumeration**
  - Detects running services and versions via `-sV` Nmap flag.
- **OS Fingerprinting**
  - Leverages Nmap OS detection (`-O`) to guess host operating systems.
- **DNS & WHOIS Lookups**
  - Fetches A, MX, NS records (`dnspython`) and WHOIS metadata (`python-whois`).
- **Web Directory Enumeration**
  - Integrates Gobuster wordlists to brute‑force common paths on web servers.
- **CVE Lookup**
  - Queries the NVD API for known vulnerabilities matching discovered service versions.
- **Netcat Utilities**
  - Banner grabbing and raw TCP interactions via custom wrappers.
- **Structured Reporting**
  - Outputs both JSON and plain‑text reports with timestamps in `reports/`.
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
   git clone https://github.com/yourusername/recon-tool.git
   cd recon-tool
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
[3] Exit
```

- **Internal Scan**: Automatically chooses an interface, discovers your `/24` subnet, runs Nmap scans in parallel, and saves `reports/internal_<IP>.json/.txt`.
- **External Scan**: Prompts for a domain or IP, performs WHOIS, DNS, Nmap, Gobuster (optional), CVE lookup, and saves `reports/external_<target>.json/.txt`.

### Command‑Line Flags
Alternatively, you can pass flags directly:
```bash
python3 main.py --internal-scan
python3 main.py --external-scan example.com --wordlist wordlists/gobuster/common.txt
```

---

## Module Descriptions

```
modules/
├── cve_lookup.py       # Query NVD API for CVEs by service/version
├── dns_enum.py         # DNS enumeration via dig/nslookup wrappers
├── external_scan.py    # Orchestrates WHOIS, DNS, Nmap, Gobuster, CVE
├── internal_scan.py    # Interface selection, subnet detection, Nmap scan
├── netcat_utils.py     # Raw TCP interactions & banner grabbing
├── nmap_scanner.py     # Wraps python-nmap for port & OS scans
└── web_enum.py         # Gobuster integration for web dir brute-forcing
```

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

1. **Quick Internal Audit**
   ```bash
   python3 main.py --internal-scan
   # Review reports/internal_<IP>.json and .txt
   ```

2. **External Recon & CVE Report**
   ```bash
   python3 main.py --external-scan example.com
   # Inspect reports/external_example_com.json
   ```

3. **Web Directory Fuzzing**
   ```bash
   python3 main.py --external-scan example.com --wordlist wordlists/gobuster/big.txt
   ```

---

## When to Use

- **Penetration Testing**: Rapidly gather host/service details.
- **Red Team Exercises**: Automate initial network map.
- **IT Audits**: Document open ports and vulnerabilities.
- **DevOps**: Validate exposed services before deployment.

---

## Contributing

Contributions, issues, and feature requests are welcome! Please open a GitHub issue or submit a pull request.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

