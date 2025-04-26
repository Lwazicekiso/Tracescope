# Paths to external tools (assumes they are in the system PATH or full path given)
NMAP_PATH = "nmap"
GOBUSTER_PATH = "gobuster"

# Default scanning flags for Nmap
# -sS: TCP SYN scan, -sV: version detection, -O: OS detection, -T4: faster timing, -Pn: skip host discovery
DEFAULT_NMAP_FLAGS = "-sS -sV -O -T4 -Pn"

# Default flags and wordlist for Gobuster (directory brute-forcing mode)
# Wordlist points to 'wordlists/gobuster/common.txt' by default
GOBUSTER_WORDLIST = "wordlists/gobuster/common.txt"
GOBUSTER_THREADS = 50
GOBUSTER_TIMEOUT = 10  # timeout in seconds for each request

# Example default gobuster command components (these can be built into CLI as needed)
# e.g., f"{GOBUSTER_PATH} dir -u <URL> -w {GOBUSTER_WORDLIST} -t {GOBUSTER_THREADS} -to {GOBUSTER_TIMEOUT}"
