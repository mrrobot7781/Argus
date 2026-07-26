"""
Argus Service Intelligence Database
"""

SERVICE_DB = {

    "sshd": {
        "service": "SSH",
        "risk": "LOW",
        "description": "Secure remote administration",
        "recommendation": "Disable root login and use SSH keys."
    },

    "apache2": {
        "service": "Apache Web Server",
        "risk": "LOW",
        "description": "HTTP Web Server",
        "recommendation": "Keep updated and enable HTTPS."
    },

    "nginx": {
        "service": "NGINX",
        "risk": "LOW",
        "description": "Reverse Proxy / Web Server",
        "recommendation": "Enable TLS and security headers."
    },

    "mysql": {
        "service": "MySQL",
        "risk": "MEDIUM",
        "description": "Database Server",
        "recommendation": "Restrict remote connections."
    },

    "postgres": {
        "service": "PostgreSQL",
        "risk": "MEDIUM",
        "description": "Database Server",
        "recommendation": "Allow only trusted hosts."
    },

    "redis-server": {
        "service": "Redis",
        "risk": "CRITICAL",
        "description": "In-Memory Database",
        "recommendation": "Enable authentication and bind to localhost."
    },

    "mongod": {
        "service": "MongoDB",
        "risk": "CRITICAL",
        "description": "NoSQL Database",
        "recommendation": "Enable authentication."
    },

    "docker": {
        "service": "Docker",
        "risk": "LOW",
        "description": "Container Runtime",
        "recommendation": "Restrict Docker socket."
    },

    "containerd": {
        "service": "Containerd",
        "risk": "LOW",
        "description": "Container Runtime",
        "recommendation": "Keep updated."
    },

    "grafana": {
        "service": "Grafana",
        "risk": "LOW",
        "description": "Monitoring Dashboard",
        "recommendation": "Enable authentication."
    },

    "prometheus": {
        "service": "Prometheus",
        "risk": "LOW",
        "description": "Monitoring",
        "recommendation": "Restrict access."
    },

    "node": {
        "service": "Node.js",
        "risk": "MEDIUM",
        "description": "JavaScript Runtime",
        "recommendation": "Don't expose development servers."
    },

    "python3": {
        "service": "Python Application",
        "risk": "MEDIUM",
        "description": "Python Server",
        "recommendation": "Verify application exposure."
    },

    "java": {
        "service": "Java Application",
        "risk": "MEDIUM",
        "description": "Java Server",
        "recommendation": "Verify exposed services."
    },

    "ollama": {
        "service": "Ollama AI Server",
        "risk": "LOW",
        "description": "Local LLM Server",
        "recommendation": "Expose only if required."
    }
}
