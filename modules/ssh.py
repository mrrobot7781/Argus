
"""
Argus - SSH Security Audit Module

Audits the SSH server configuration and reports common security issues.
"""

import os


SSH_CONFIG = "/etc/ssh/sshd_config"


def get_config_value(key):
    """
    Return the value of a configuration option from sshd_config.
    Ignores commented lines.
    """
    try:
        with open(SSH_CONFIG, "r") as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                parts = line.split()

                if len(parts) >= 2 and parts[0] == key:
                    return parts[1]

    except FileNotFoundError:
        return None

    return None


def run():
    """
    Perform SSH security audit.
    """

    if not os.path.exists(SSH_CONFIG):
        return {
            "module": "SSH Audit",
            "status": "WARNING",
            "severity": "MEDIUM",
            "data": {
                "SSH Installed": "No",
                "Message": "OpenSSH Server is not installed."
            }
        }

    permit_root = get_config_value("PermitRootLogin")
    password_auth = get_config_value("PasswordAuthentication")
    pubkey_auth = get_config_value("PubkeyAuthentication")
    empty_passwords = get_config_value("PermitEmptyPasswords")
    ssh_port = get_config_value("Port")

    status = "PASS"
    severity = "INFO"

    recommendations = []

    if permit_root and permit_root.lower() == "yes":
        status = "WARNING"
        severity = "HIGH"
        recommendations.append("Disable root login (PermitRootLogin no).")

    if password_auth and password_auth.lower() == "yes":
        recommendations.append("Consider disabling password authentication.")

    if empty_passwords and empty_passwords.lower() == "yes":
        status = "CRITICAL"
        severity = "HIGH"
        recommendations.append("Disable empty passwords immediately.")

    data = {
        "SSH Installed": "Yes",
        "SSH Port": ssh_port if ssh_port else "22 (Default)",
        "Root Login": permit_root if permit_root else "Default",
        "Password Authentication": password_auth if password_auth else "Default",
        "Public Key Authentication": pubkey_auth if pubkey_auth else "Default",
        "Empty Passwords": empty_passwords if empty_passwords else "Default",
        "Recommendations": (
            "\n• " + "\n• ".join(recommendations)
            if recommendations else
            "System follows basic SSH security practices."
        )
    }

    return {
        "module": "SSH Audit",
        "status": status,
        "severity": severity,
        "data": data
    }

