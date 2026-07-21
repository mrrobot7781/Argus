"""
ARGUS v1.0
Automated Linux Security Auditing Framework
"""

from modules import system


def banner():
    print("=" * 55)
    print("               ARGUS v1.0")
    print(" Automated Linux Security Auditing Framework")
    print("=" * 55)


def main():

    banner()

    print("\n[*] Collecting System Information...\n")

    info = system.run()

    for key, value in info.items():
        print(f"{key:<20}: {value}")

    print("\n[✓] System Information Collected Successfully")


if __name__ == "__main__":
    main()
