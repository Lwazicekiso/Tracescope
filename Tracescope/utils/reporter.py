import json
import os

def export_report(domain, report_data):
    if not os.path.exists("reports"):
        os.makedirs("reports")

    txt_path = f"reports/{domain}_report.txt"
    json_path = f"reports/{domain}_report.json"

    with open(txt_path, "w") as f:
        for key, val in report_data.items():
            f.write(f"\n=== {key.upper()} ===\n")
            f.write(f"{json.dumps(val, indent=2)}\n")

    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2)
