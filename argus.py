"""
ARGUS v1.0
Automated Linux Security Auditing Framework
"""

from modules import system, users, ssh, firewall
from utils import formatter
from utils.banner import show_banner


def print_module(result):

    formatter.header(result["module"])

    for key, value in result["data"].items():
        print(f"{key:<35}: {value}")

    print("-" * 70)

    print(
        f"{'Status':<35}: "
        f"{formatter.status_color(result['status'])}"
    )

    print(
        f"{'Severity':<35}: "
        f"{formatter.severity_color(result['severity'])}"
    )

    print("-" * 70)



def main():
    """Main entry point for Argus."""

    show_banner()

    print("\nStarting Linux Security Audit...\n")

    modules = [
        system.run,
        users.run,
        ssh.run,
        firewall.run,
    ]

    for module in modules:
        result = module()
        print_module(result)

    print("\n" + "=" * 70)
    print("ARGUS SECURITY AUDIT COMPLETED")
    print("=" * 70)
    print("Modules Executed : {}".format(len(modules)))
    print("Status           : SUCCESS")
    print("=" * 70)


if __name__ == "__main__":
    main()


