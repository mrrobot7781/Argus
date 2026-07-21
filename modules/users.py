"""
Argus - User Audit Module

Audits Linux user accounts and authentication activity.
"""

import getpass
import grp
import subprocess


def get_recent_logins():
    """
    Returns users who logged in during the last 5 days.
    """

    recent_logins = []

    try:
        result = subprocess.run(
            ["last", "-s", "-5days"],
            capture_output=True,
            text=True
        )

        for line in result.stdout.splitlines():

            if (
                not line.strip()
                or line.startswith("wtmp begins")
                or line.startswith("reboot")
            ):
                continue

            username = line.split()[0]

            # Avoid duplicates
            if username not in recent_logins:
                recent_logins.append(username)

    except Exception:
        recent_logins.append("Unable to fetch login history")

    return recent_logins


def run():
    """
    Perform a Linux user audit.

    Returns:
        dict
    """

    users = []

    # Read all local users
    with open("/etc/passwd", "r") as passwd_file:
        for line in passwd_file:
            users.append(line.split(":")[0])

    current_user = getpass.getuser()

    root_exists = "Yes" if "root" in users else "No"

    # Get sudo users
    sudo_users = []

    try:
        sudo_group = grp.getgrnam("sudo")
        sudo_users = sudo_group.gr_mem
    except KeyError:
        sudo_users = []

    recent_logins = get_recent_logins()

    user_info = {
        "Current User": current_user,
        "Total Users": len(users),
        "Root Account": root_exists,
        "Sudo Users": ", ".join(sudo_users) if sudo_users else "None",
        "Users Logged In (Last 5 Days)": ", ".join(recent_logins)
        if recent_logins else "None"
    }

    return {
        "module": "User Audit",
        "status": "PASS",
        "severity": "INFO",
        "data": user_info
    }

