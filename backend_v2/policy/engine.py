import ipaddress
import os
import socket
from urllib.parse import urlparse


class PolicyViolationError(Exception):
    pass


def validate(target_url: str) -> None:
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        raise PolicyViolationError("Only HTTP/HTTPS targets are allowed")

    hostname = parsed.hostname or ""
    if not hostname:
        raise PolicyViolationError("Target URL must include a valid hostname")

    try:
        resolved_ip = socket.gethostbyname(hostname)
    except Exception as exc:
        raise PolicyViolationError(f"Cannot resolve target hostname: {exc}") from exc

    ip = ipaddress.ip_address(resolved_ip)

    if ip.is_loopback and os.getenv("ALLOW_LOCALHOST", "").lower() != "true":
        raise PolicyViolationError("Scanning localhost is blocked. Set ALLOW_LOCALHOST=true to override")

    if not ip.is_loopback and ip.is_private and os.getenv("ALLOW_INTERNAL", "").lower() != "true":
        raise PolicyViolationError("Scanning private/internal networks is blocked")

    if ip.is_link_local or ip.is_reserved or ip.is_multicast:
        raise PolicyViolationError("Target resolves to a reserved or non-routable address")

    allowed_domains = os.getenv("ALLOWED_DOMAINS", "")
    if allowed_domains:
        allowed = {item.strip().lower() for item in allowed_domains.split(",") if item.strip()}
        if hostname.lower() not in allowed:
            raise PolicyViolationError("Target hostname is not in the allowed domains list")

    blocked_paths = ["/delete", "/drop", "/reset", "/admin/nuke"]
    if any(parsed.path.lower().startswith(path) for path in blocked_paths):
        raise PolicyViolationError("Target path is blocked by policy")
