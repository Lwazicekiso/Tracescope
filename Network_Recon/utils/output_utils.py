# utils/output_utils.py

import json
import os
from datetime import datetime

def print_status(message):
    """
    Print a timestamped status message.
    """
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {message}")

def save_report(domain, raw_data):
    """
    Wrap raw_data into our standard JSON/TXT structures and write to /reports.
    """
    # Prepare report structure
    ts = datetime.utcnow().isoformat() + "Z"
    summary = {
        "whois": raw_data.get("whois", {}),
        "dns_records": raw_data.get("dns", {}),
        "open_ports": raw_data.get("open_ports", [])
    }
    # Add notes if no open_ports found
    if not summary["open_ports"]:
        summary["notes"] = "No common ports detected."

    report = {
        "target": domain,
        "timestamp": ts,
        "recon_summary": summary
    }

    # Ensure reports folder exists
    if not os.path.isdir("reports"):
        os.makedirs("reports")

    # File paths
    time_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"reports/{domain}_report_{time_tag}.json"
    txt_path  = f"reports/{domain}_report_{time_tag}.txt"

    # Save JSON
    with open(json_path, "w") as jf:
        json.dump(report, jf, indent=2)

    # Save human-readable TXT
    with open(txt_path, "w") as tf:
        tf.write(f"Report for {domain} (Generated: {ts})\n\n")
        for section, data in report["recon_summary"].items():
            tf.write(f"=== {section.upper()} ===\n")
            tf.write(json.dumps(data, indent=2))
            tf.write("\n\n")

    print_status(f"📝 Reports saved:\n   • {json_path}\n   • {txt_path}")
