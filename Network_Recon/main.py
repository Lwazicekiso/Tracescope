# main.py

import sys
from external_scan import run_external_scan
from internal_scan import run_internal_scan

def print_banner():
    print(r"""
╔══════════════════════════════╗
║        NETWORK RECON         ║
╚══════════════════════════════╝
    """)

def main_menu():
    while True:
        print("\nSelect an option:")
        print("[1] External Domain Scan")
        print("[2] Internal Network Scan")
        print("[3] Exit")
        
        choice = input("\n> ").strip()
        
        if choice == '1':
            domain = input("Enter domain (e.g., example.com): ").strip()
            if domain:
                run_external_scan(domain)
            else:
                print("[!] Invalid domain input.")
        
        elif choice == '2':
            run_internal_scan()

        elif choice == '3':
            print("Goodbye! 👋")
            sys.exit()

        else:
            print("[!] Invalid selection. Please choose 1, 2, or 3.")

if __name__ == "__main__":
    try:
        print_banner()
        main_menu()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")
        sys.exit()
