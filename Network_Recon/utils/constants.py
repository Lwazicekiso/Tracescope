# utils/constants.py

# Top 10 commonly used ports & their default service names
COMMON_PORTS = {
    21:  "FTP",
    22:  "SSH",
    23:  "Telnet",
    25:  "SMTP",
    53:  "DNS",
    80:  "HTTP",
    110: "POP3",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB"
}

# Patterns to extract version info from banners
VERSION_PATTERNS = [
    (r"OpenSSH[_/](\S+)",            "SSH"),
    (r"Apache[/ ](\S+)",             "Apache"),
    (r"nginx[/ ](\S+)",              "Nginx"),
    (r"Microsoft-IIS[/ ](\S+)",      "IIS"),
    (r"FTP server.*?(\d+\.\d+)",     "FTP"),
    (r"MySQL\s+(\d+\.\d+\.\d+)",     "MySQL"),
    (r"PostgreSQL\s+(\d+\.\d+)",     "PostgreSQL")
]
