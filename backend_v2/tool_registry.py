import httpx
from bs4 import BeautifulSoup
from urllib.parse import urldefrag, urljoin, urlparse
from langchain_core.tools import tool
from backend_v2.tools.recon_helper import normalize_url

from backend_v2.tools.security_headers_checker import security_headers_checker
from backend_v2.tools.file_upload_tester import file_upload_tester
from backend_v2.tools.xss_tester import xss_tester
from backend_v2.tools.sql_injection_tester import sql_injection_tester
from backend_v2.tools.port_scanner import port_scanner


@tool
def web_crawler(target: str) -> str:
    """Discovers endpoints on the target web application safely."""
    target_url = normalize_url(target)
    target_url, _ = urldefrag(target_url)
    target_host = urlparse(target_url).netloc
    timeout = httpx.Timeout(connect=5.0, read=12.0, write=5.0, pool=5.0)
    headers = {
        "User-Agent": "PortBiter/3.0 security scanner",
        "Accept": "text/html,application/xhtml+xml",
    }

    for attempt in range(2):
        try:
            with httpx.Client(
                timeout=timeout,
                follow_redirects=True,
                verify=False,
                headers=headers,
            ) as client:
                response = client.get(target_url)
            if response.status_code >= 400:
                return f"Crawler failed: target returned HTTP {response.status_code}"

            soup = BeautifulSoup(response.text[:2_000_000], "html.parser")
            endpoints = []
            seen = set()
            for anchor in soup.find_all("a", href=True):
                full_url, _ = urldefrag(urljoin(str(response.url), anchor["href"]))
                parsed = urlparse(full_url)
                if parsed.scheme not in {"http", "https"} or parsed.netloc != target_host:
                    continue
                if full_url not in seen:
                    seen.add(full_url)
                    endpoints.append(full_url)
                if len(endpoints) == 10:
                    break
            return f"Crawled endpoints: {endpoints}"
        except httpx.TimeoutException as exc:
            if attempt == 1:
                return f"Crawler failed after 2 attempts: request timed out ({exc})"
        except httpx.RequestError as exc:
            if attempt == 1:
                return f"Crawler failed after 2 attempts: {exc}"
        except Exception as exc:
            return f"Crawler failed: {exc}"

    return "Crawler failed after 2 attempts: request did not complete"


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
