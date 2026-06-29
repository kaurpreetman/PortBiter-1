import socket
from urllib.parse import urlparse
from langchain_core.tools import tool


@tool
def port_scanner(target: str) -> str:
    """Performs a lightweight port scan against the target host using a short list of common ports."""
    try:
        parsed = urlparse(target if target.startswith("http") else f"http://{target}")
        host = parsed.hostname
        if not host:
            return f"Port scanner error: invalid target {target}"

        ports = [21, 22, 25, 53, 80, 110, 143, 443, 8080, 8443]
        open_ports = []
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=2):
                    open_ports.append(port)
            except OSError:
                continue

        if open_ports:
            return f"OPEN PORTS: {host} has ports {', '.join(str(port) for port in open_ports)} open"
        return f"No common open ports detected on {host}"
    except Exception as exc:
        return f"Port scanner error: {exc}"
