#!/usr/bin/env python3
# main.py

import sys
from modules.internal_scan import run_internal_scan
from modules.external_scan import run_external_scan
from utils.output_utils     import print_status, save_report

def main():
    while True:
        print("\n=== Network Recon Tool ===")
        print("[1] Internal Scan")
        print("[2] External Scan")
        print("[3] Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            print_status("Starting Internal Scan...")
            report = run_internal_scan()
            if report:
                try:
                    prefix = f"internal_{report['local_ip'].replace('.', '_')}"
                    save_report(report, prefix)
                    print_status("✅ Internal report saved.")
                except Exception as e:
                    print_status(f"❌ Failed to save internal report: {e}")
            else:
                print_status("⚠️  No data to save for internal scan.")

        elif choice == "2":
            target = input("Enter target domain or IP: ").strip()
            if not target:
                print_status("⚠️  No target provided.")
                continue
            print_status(f"Starting External Scan on {target}...")
            report = run_external_scan(target)
            if report:
                try:
                    safe = target.replace('.', '_').replace(':', '_').replace('/', '_')
                    prefix = f"external_{safe}"
                    save_report(report, prefix)
                    print_status("✅ External report saved.")
                except Exception as e:
                    print_status(f"❌ Failed to save external report: {e}")
            else:
                print_status("⚠️  No data to save for external scan.")

        elif choice == "3":
            print_status("Exiting. Goodbye!")
            sys.exit(0)
        else:
            print_status("❌ Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
