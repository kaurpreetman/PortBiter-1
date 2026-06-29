import httpx
from langchain_core.tools import tool


@tool
def header_checker(target: str) -> str:
    """Checks a target URL for missing or misconfigured security headers."""
    try:
        response = httpx.get(target, timeout=8.0, follow_redirects=True, verify=False)
        headers = {key.lower(): value for key, value in response.headers.items()}
        findings = []

        checks = [
            ("content-security-policy", None, "HIGH", "Missing CSP allows XSS and injection attacks"),
            ("strict-transport-security", None, "HIGH", "Missing HSTS weakens HTTPS protection"),
            ("x-frame-options", None, "MEDIUM", "Missing X-Frame-Options allows clickjacking"),
            ("x-content-type-options", "nosniff", "MEDIUM", "Missing nosniff allows MIME sniffing"),
            ("referrer-policy", None, "LOW", "Missing Referrer-Policy leaks referrer metadata"),
            ("permissions-policy", None, "LOW", "Missing Permissions-Policy allows feature abuse"),
        ]

        for name, expected, severity, description in checks:
            value = headers.get(name)
            if not value:
                findings.append(f"MISSING HEADER [{severity}]: {name} - {description}")
            elif expected and expected.lower() not in value.lower():
                findings.append(f"WEAK HEADER [{severity}]: {name} = {value} - {description}")
            elif name == "x-frame-options" and value.lower() not in {"deny", "sameorigin"}:
                findings.append(f"WEAK HEADER [MEDIUM]: x-frame-options = {value} - clickjacking protection is weak")

        if findings:
            return "\n".join(findings)
        return f"Security headers look good on {target}"
    except Exception as exc:
        return f"Header checker error: {exc}"
