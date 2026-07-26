"""
ARGUS v1.0
Automated Linux Security Auditing Framework
"""

from rich.progress import Progress
import time

from modules import system, users, ssh, firewall, ports

from utils.banner import show_banner
from utils.display import print_module


def main():
    """Main entry point for Argus."""

    show_banner()

    print("\n[+] Starting Linux Security Audit...\n")

    # List of audit modules
    modules = [
        system.run,
        users.run,
        ssh.run,
        firewall.run,
        ports.run,
    ]

    results = []

    # Progress Bar
    with Progress() as progress:

        task = progress.add_task(
            "[cyan]Running Security Audit...",
            total=len(modules)
        )

        for module in modules:

            result = module()

            results.append(result)

            time.sleep(0.5)

            progress.advance(task)

    # Display Results
    for result in results:
        print_module(result)

    # Final Summary
    print("\n" + "=" * 70)
    print("               ARGUS SECURITY AUDIT COMPLETED")
    print("=" * 70)
    print(f"Modules Executed : {len(modules)}")
    print("Status           : SUCCESS")
    print("=" * 70)


if __name__ == "__main__":
    main()
