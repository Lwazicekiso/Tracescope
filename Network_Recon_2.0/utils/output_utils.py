# utils/output_utils.py

import os
import json
from datetime import datetime

def print_status(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{timestamp} {message}")

def save_json(results, filename):
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", f"{filename}.json")
    try:
        with open(path, 'w') as f:
            json.dump(results, f, indent=4)
        print_status(f"Results saved to {path}")
    except Exception as e:
        print_status(f"❌ Failed to save JSON report: {repr(e)}")

def save_txt(results, filename):
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", f"{filename}.txt")
    try:
        with open(path, 'w') as f:
            if isinstance(results, dict):
                for k, v in results.items():
                    f.write(f"{k}: {v}\n")
            elif isinstance(results, list):
                for item in results:
                    f.write(f"{item}\n")
            else:
                f.write(str(results))
        print_status(f"Results saved to {path}")
    except Exception as e:
        print_status(f"❌ Failed to save text report: {repr(e)}")

def save_report(data, filename_prefix):
    """
    Wrapper: save both JSON and TXT with same prefix.
    """
    save_json(data, filename_prefix)
    save_txt(data, filename_prefix)
