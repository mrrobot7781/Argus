
"""
Argus - Firewall Audit Module

Audits Linux firewall configuration.
Supports:
- UFW
- Firewalld
- iptables
"""

import shutil
import subprocess


def run_command(command):
    """
    Execute a shell command and return its output.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        return result.stdout.strip()

    except Exception:
        return ""


def check_ufw():

    if not shutil.which("ufw"):
        return None

    output = run_command(["ufw", "status"])

    enabled = "inactive" not in output.lower()

    incoming = "Unknown"
    outgoing = "Unknown"

    for line in output.splitlines():

        if line.startswith("Default:"):

            defaults = line.replace("Default:", "").strip()

            parts = defaults.split(",")

            if len(parts) >= 2:
                incoming = parts[0].strip()
                outgoing = parts[1].strip()

    return {
        "Firewall": "UFW",
        "Enabled": enabled,
        "Incoming": incoming,
        "Outgoing": outgoing
    }


def check_firewalld():

    if not shutil.which("firewall-cmd"):
        return None

    state = run_command(["firewall-cmd", "--state"])

    return {
        "Firewall": "Firewalld",
        "Enabled": state == "running",
        "Incoming": "Managed by Zones",
        "Outgoing": "Managed by Zones"
    }


def check_iptables():

    if not shutil.which("iptables"):
        return None

    rules = run_command(["iptables", "-L"])

    rule_count = len(rules.splitlines())

    return rule_count


def run():

    ufw = check_ufw()
    firewalld = check_firewalld()
    iptables_rules = check_iptables()

    firewall_name = "None"
    enabled = False
    incoming = "Unknown"
    outgoing = "Unknown"

    if ufw:
        firewall_name = ufw["Firewall"]
        enabled = ufw["Enabled"]
        incoming = ufw["Incoming"]
        outgoing = ufw["Outgoing"]

    elif firewalld:
        firewall_name = firewalld["Firewall"]
        enabled = firewalld["Enabled"]
        incoming = firewalld["Incoming"]
        outgoing = firewalld["Outgoing"]

    recommendations = []

    status = "PASS"
    severity = "INFO"

    if firewall_name == "None":

        status = "WARNING"
        severity = "HIGH"

        recommendations.append(
            "Install and configure a firewall."
        )

    elif not enabled:

        status = "WARNING"
        severity = "HIGH"

        recommendations.append(
            "Enable the firewall."
        )

    if iptables_rules is not None and iptables_rules < 10:

        recommendations.append(
            "Very few iptables rules detected."
        )

    data = {

        "Firewall Detected": firewall_name,
        "Firewall Enabled": "Yes" if enabled else "No",
        "Default Incoming Policy": incoming,
        "Default Outgoing Policy": outgoing,
        "iptables Rules": (
            iptables_rules
            if iptables_rules is not None
            else "Not Installed"
        ),
        "Recommendations": (
            "\n• " + "\n• ".join(recommendations)
            if recommendations
            else "Firewall configuration looks secure."
        )
    }

    return {

        "module": "Firewall Audit",
        "status": status,
        "severity": severity,
        "data": data
    }

