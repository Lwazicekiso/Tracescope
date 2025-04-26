import subprocess
import os

def web_enum(target, wordlist=None):
    """
    Perform directory enumeration on the given target domain/IP using Gobuster.
    - target: The target URL or domain (e.g., "example.com" or "http://example.com").
    - wordlist: Optional path to a custom wordlist file (defaults to "wordlists/gobuster/common.txt").
    Returns a dictionary with target, wordlist, and a list of found paths (each with status code).
    """
    # Determine wordlist path
    default_wordlist = os.path.join("wordlists", "gobuster", "common.txt")
    wordlist_path = wordlist if wordlist else default_wordlist
    # Ensure target has URL scheme
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    print(f"[+] Starting Gobuster directory enumeration on {target} with wordlist {wordlist_path}")
    results = []
    try:
        # Run gobuster in dir mode
        cmd = ["gobuster", "dir", "-u", target, "-w", wordlist_path]
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
        output = completed.stdout
        if completed.returncode != 0:
            print(f"[-] Gobuster returned exit code {completed.returncode}:")
            print(completed.stderr.strip())
        # Parse gobuster output lines for found paths (lines usually start with '/')
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Gobuster") or line.startswith("[") or line.startswith("Error"):
                continue
            # Gobuster found entry (e.g., "/admin (Status: 200)")
            parts = line.split()
            path = parts[0]
            status = None
            if "(Status:" in line:
                try:
                    status = int(line.split("(Status:")[1].split(")")[0])
                except Exception:
                    status = None
            results.append({"path": path, "status": status})
        print(f"[+] Gobuster enumeration completed. Found {len(results)} paths.")
    except subprocess.TimeoutExpired:
        print("[-] Gobuster command timed out.")
        return {"error": "Gobuster command timed out"}
    except FileNotFoundError:
        print("[-] Gobuster is not installed or not found in PATH.")
        return {"error": "Gobuster not found"}
    except Exception as e:
        print(f"[-] Error running Gobuster: {e}")
        return {"error": str(e)}
    return {"target": target, "wordlist": wordlist_path, "results": results}
