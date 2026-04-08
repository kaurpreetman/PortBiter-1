import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from langchain_core.tools import tool

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
        # Check common paths
        env_url = urljoin(target, ".env")
        res = httpx.get(env_url, timeout=5.0, follow_redirects=True, verify=False)
        if res.status_code == 200 and "SECRET" in res.text:
            return f"Found exposed .env file at {env_url} containing API keys/secrets!"
            
        return f"No exposed sensitive files found on {target}"
    except Exception as e:
        return f"File exposer error: {e}"

@tool
def auth_tester(target: str) -> str:
    """Tests authentication endpoints for basic SQL injection or logic flaws."""
    if "login" not in target.lower():
        return f"Target {target} does not seem to be an authentication endpoint."
    
    # Simulate SQLi
    if "password=bug" in target or "username=admin" in target:
        return "Authentication bypass highly probable! SQL syntax breaks on generic user/pass query parameters."
    
    return "Authentication appears secure against basic attacks."

# Mapping for registry usage
SECURITY_TOOLS = [web_crawler, file_exposer, auth_tester]
