"""
Argus - System Information Module

Collects basic system information required for the security audit.
"""

import platform
import socket
import psutil
from datetime import datetime


def run():
    """Collect system information."""

    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot_time

    system_info = {
        "Hostname": socket.gethostname(),
        "Operating System": platform.system(),
        "OS Release": platform.release(),
        "Kernel Version": platform.version(),
        "Architecture": platform.machine(),
        "Processor": platform.processor(),
        "CPU Cores": psutil.cpu_count(logical=True),
        "RAM (GB)": round(psutil.virtual_memory().total / (1024 ** 3), 2),
        "Disk Usage (%)": psutil.disk_usage("/").percent,
        "Boot Time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
        "Uptime": str(uptime).split(".")[0]
    }

    return system_info
