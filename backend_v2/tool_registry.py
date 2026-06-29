import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from langchain_core.tools import tool

from backend_v2.tools.security_headers_checker import security_headers_checker
from backend_v2.tools.file_upload_tester import file_upload_tester
from backend_v2.tools.xss_tester import xss_tester
from backend_v2.tools.sql_injection_tester import sql_injection_tester
from backend_v2.tools.port_scanner import port_scanner


@tool
def web_crawler(target: str) -> str:
    """Discovers endpoints on the target web application safely."""
    try:
        res = httpx.get(target, timeout=10.0, follow_redirects=True, verify=False)
        soup = BeautifulSoup(res.text, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(target, href)
            if urlparse(full_url).netloc == urlparse(target).netloc:
                links.append(full_url)
        endpoints = list(set(links))[:5]
        return f"Crawled endpoints: {endpoints}"
    except Exception as e:
        return f"Crawler failed: {str(e)}"


@tool
def file_exposer(target: str) -> str:
    """Tests for exposed sensitive files like .env or configuration files."""
    try:
        env_url = urljoin(target, ".env")
        res = httpx.get(env_url, timeout=5.0, follow_redirects=True, verify=False)
        if res.status_code == 200 and "SECRET" in res.text:
            return f"Found exposed .env file at {env_url} containing API keys/secrets!"

        return f"No exposed sensitive files found on {target}"
    except Exception as e:
        return f"File exposer error: {e}"


@tool
def auth_tester(target: str) -> str:
    """Tests authentication endpoints for basic SQL injection using safe payloads."""
    try:
        candidates = []
        if any(token in target.lower() for token in ["login", "auth", "signin"]):
            candidates.append(target)

        response = httpx.get(target, timeout=8.0, follow_redirects=True, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"]
            full_url = urljoin(target, href)
            if any(token in full_url.lower() for token in ["login", "auth", "signin"]):
                candidates.append(full_url)
        for form in soup.find_all("form", action=True):
            action = form["action"]
            full_url = urljoin(target, action)
            if any(token in full_url.lower() for token in ["login", "auth", "signin"]):
                candidates.append(full_url)

        candidate_urls = list(dict.fromkeys(candidates))[:3]
        if not candidate_urls:
            return f"No authentication endpoint found at or linked from {target}"

        payloads = [("admin' OR '1'='1", "x"), ("' OR 1=1--", "x"), ("admin'--", "x")]
        for auth_url in candidate_urls:
            for username_payload, password_payload in payloads:
                try:
                    get_res = httpx.get(auth_url, params={"username": username_payload, "password": password_payload}, timeout=8.0, follow_redirects=True, verify=False)
                    if any(marker in get_res.text.lower() for marker in ["success", "welcome", "dashboard", "logged in", "admin"]):
                        return f"SQL INJECTION FOUND: auth bypass-like response on {auth_url} using payload {username_payload}"

                    post_res = httpx.post(auth_url, data={"username": username_payload, "password": password_payload}, timeout=8.0, follow_redirects=True, verify=False)
                    if any(marker in post_res.text.lower() for marker in ["success", "welcome", "dashboard", "logged in", "admin"]):
                        return f"SQL INJECTION FOUND: auth bypass-like response on {auth_url} using payload {username_payload}"
                except Exception:
                    continue

        return f"Authentication endpoint at {candidate_urls[0]} appears secure against basic SQL injection"
    except Exception as exc:
        return f"Auth tester error: {exc}"


# Mapping for registry usage
SECURITY_TOOLS = [
    web_crawler,
    file_exposer,
    auth_tester,
    xss_tester,
    sql_injection_tester,
    security_headers_checker,
    file_upload_tester,
    port_scanner,
]
