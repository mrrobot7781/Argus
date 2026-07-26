"""
Argus - Open Ports Audit
"""
from data.services import SERVICE_DB
import subprocess

SERVICE_MAP = {

    # FTP
    20: "FTP Data",
    21: "FTP",

    # SSH / Remote Access
    22: "SSH",
    23: "Telnet",

    # Mail
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",

    # DNS
    53: "DNS",

    # DHCP
    67: "DHCP Server",
    68: "DHCP Client",

    # Time
    123: "NTP",

    # SNMP
    161: "SNMP",
    162: "SNMP Trap",

    # LDAP
    389: "LDAP",
    636: "LDAPS",

    # HTTP
    80: "HTTP",
    81: "HTTP Alternate",
    443: "HTTPS",
    444: "HTTPS Alternate",
    8080: "HTTP Proxy",
    8081: "HTTP Alternate",
    8000: "HTTP Dev Server",
    8008: "HTTP Alt",
    8888: "Jupyter Notebook",

    # Databases
    1433: "Microsoft SQL Server",
    1434: "MS SQL Monitor",
    1521: "Oracle Database",
    3306: "MySQL",
    33060: "MySQL X Protocol",
    5432: "PostgreSQL",
    5433: "PostgreSQL Alt",
    6379: "Redis",
    6380: "Redis SSL",
    9042: "Cassandra",
    27017: "MongoDB",
    27018: "MongoDB Config",
    27019: "MongoDB Router",

    # Web Servers
    8088: "HTTP Server",
    8443: "HTTPS Admin",

    # Remote Desktop
    3389: "RDP",
    5900: "VNC",
    5901: "VNC-1",
    5902: "VNC-2",

    # File Sharing
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    445: "SMB",

    # Printing
    515: "LPD",
    631: "IPP",

    # Kerberos
    88: "Kerberos",

    # RPC
    111: "RPCbind",

    # VPN
    500: "IPSec ISAKMP",
    4500: "IPSec NAT-T",
    1194: "OpenVPN",
    1701: "L2TP",
    1723: "PPTP",

    # Proxy
    3128: "Squid Proxy",

    # Containers
    2375: "Docker API",
    2376: "Docker TLS",
    2377: "Docker Swarm",

    # Kubernetes
    6443: "Kubernetes API",
    10250: "Kubelet",
    10255: "Kubelet ReadOnly",

    # Elasticsearch
    9200: "Elasticsearch",
    9300: "Elasticsearch Cluster",

    # Message Queues
    5672: "RabbitMQ",
    15672: "RabbitMQ Management",
    9092: "Kafka",
    2181: "Zookeeper",

    # Metrics
    9090: "Prometheus",
    9100: "Node Exporter",
    3000: "Grafana",

    # Dev Tools
    5173: "Vite Dev Server",
    4200: "Angular Dev Server",
    5000: "Flask Development Server",
    11434: "Ollama API",

    # Git
    9418: "Git",

    # SIP / VoIP
    5060: "SIP",
    5061: "SIPS",

    # TFTP
    69: "TFTP",

    # Syslog
    514: "Syslog",

    # X11
    6000: "X11",

    # Jenkins
    8082: "Jenkins",

    # TeamCity
    8111: "TeamCity",

    # SonarQube
    9000: "SonarQube",

    # Cockpit
    9091: "Cockpit",

    # MinIO
    9001: "MinIO Console",

    # Memcached
    11211: "Memcached",

    # Active Directory
    3268: "Global Catalog",
    3269: "Global Catalog SSL"
}

def get_risk(port, service):
    if service == "Unknown":
        return "MEDIUM"

    if port in [23, 21, 3306, 5432, 5900]:
        return "HIGH"

    if port in [6379, 2375, 27017]:
        return "CRITICAL"

    return "LOW"


def run():

    try:

        result = subprocess.run(
            ["ss", "-tulpn"],
            capture_output=True,
            text=True
        )

        listeners = []

        for line in result.stdout.splitlines():

            if line.startswith("Netid"):
                continue

            parts = line.split()

            if len(parts) < 6:
                continue

            address = parts[4]

            if ":" not in address:
                continue

            try:
                port = int(address.rsplit(":", 1)[1])
            except ValueError:
                continue

            process = "Unknown"

            if 'users:(("' in line:
                try:
                    process = line.split('users:(("')[1].split('"')[0]
                except Exception:
                    pass

            listeners.append({
                "port": port,
                "process": process
            })

        # Remove duplicate ports
        unique = {}

        for listener in listeners:
            unique[listener["port"]] = listener

        listeners = sorted(unique.values(), key=lambda x: x["port"])

        findings = {}
        recommendations = []

        overall = "PASS"
        severity = "INFO"

        icons = {
            "LOW": "🟢 LOW",
            "MEDIUM": "🟡 MEDIUM",
            "HIGH": "🔴 HIGH",
            "CRITICAL": "🚨 CRITICAL"
        }

        for listener in listeners:

            port = listener["port"]
            process = listener["process"]

            # -----------------------------
            # Detect service
            # -----------------------------

            if port in SERVICE_MAP:

                service = SERVICE_MAP[port]
                risk = get_risk(port, service)
                recommendation = ""

            elif process in SERVICE_DB:

                info = SERVICE_DB[process]

                service = info["service"]
                risk = info["risk"]
                recommendation = info["recommendation"]

            else:

                service = "Unknown Service"
                risk = "MEDIUM"
                recommendation = "Investigate this service manually."

            findings[f"Port {port}"] = (
                f"{service} | "
                f"Process: {process} | "
                f"{icons[risk]}"
            )

            if recommendation:
                recommendations.append(recommendation)

            if risk == "MEDIUM":

                if overall == "PASS":
                    overall = "WARNING"
                    severity = "MEDIUM"

            elif risk == "HIGH":

                overall = "WARNING"
                severity = "HIGH"

            elif risk == "CRITICAL":

                overall = "CRITICAL"
                severity = "CRITICAL"

        if recommendations:

            recommendations = sorted(set(recommendations))

            findings["Recommendations"] = "\n• " + "\n• ".join(recommendations)

        else:

            findings["Recommendations"] = "✔ No dangerous exposed services found."

        return {
            "module": "Open Ports Audit",
            "status": overall,
            "severity": severity,
            "data": findings
        }

    except Exception as e:

        return {
            "module": "Open Ports Audit",
            "status": "WARNING",
            "severity": "MEDIUM",
            "data": {
                "Error": str(e)
            }
        }
