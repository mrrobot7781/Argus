"""
Argus Output Formatter
"""

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def status_color(status):
    status = status.upper()

    if status == "PASS":
        return f"{GREEN}PASS{RESET}"

    elif status == "WARNING":
        return f"{YELLOW}WARNING{RESET}"

    elif status == "CRITICAL":
        return f"{RED}CRITICAL{RESET}"

    return status


def severity_color(severity):
    severity = severity.upper()

    if severity == "INFO":
        return f"{BLUE}INFO{RESET}"

    elif severity == "LOW":
        return f"{GREEN}LOW{RESET}"

    elif severity == "MEDIUM":
        return f"{YELLOW}MEDIUM{RESET}"

    elif severity == "HIGH":
        return f"{RED}HIGH{RESET}"

    return severity


def header(title):
    print()
    print(CYAN + "=" * 70 + RESET)
    print(BOLD + f"MODULE : {title}" + RESET)
    print(CYAN + "=" * 70 + RESET)

