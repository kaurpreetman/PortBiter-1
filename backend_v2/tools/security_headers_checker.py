import httpx
from langchain_core.tools import tool
from backend_v2.tools.recon_helper import normalize_url


def _cookie_flags(header_value: str) -> dict:
    return {
        "secure": "secure" in header_value.lower(),
        "httponly": "httponly" in header_value.lower(),
        "samesite": "samesite" in header_value.lower(),
    }


@tool
def security_headers_checker(target: str) -> str:
    """Fetches a target and reports on missing security response headers and cookie flags."""
    try:
        target_url = normalize_url(target)
        res = httpx.get(target_url, timeout=8.0, follow_redirects=True, verify=False)
        headers = {k.lower(): v for k, v in res.headers.items()}
        missing = []

        required = [
            "x-frame-options",
            "x-content-type-options",
            "content-security-policy",
            "strict-transport-security",
            "referrer-policy",
            "permissions-policy",
        ]

        for header in required:
            if header not in headers:
                missing.append(header)

        cookie_report = []
        raw_cookies = res.headers.get("set-cookie")
        if raw_cookies:
            flags = _cookie_flags(raw_cookies)
            for name, present in flags.items():
                if not present:
                    cookie_report.append(name)

        message = []
        if missing:
            message.append(f"Missing headers: {', '.join(missing)}")
        else:
            message.append("Security headers present.")
        if cookie_report:
            message.append(f"Cookie flags missing: {', '.join(cookie_report)}")
        else:
            message.append("Cookie flags look good or no cookies set.")

        return f"SECURITY HEADERS: {'; '.join(message)}"
    except Exception as exc:
        return f"Security header checker error: {exc}"
