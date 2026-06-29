import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode
from typing import Dict, List, Optional


def normalize_url(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.scheme:
        target = f"http://{target}"
    return target


def fetch_html(target: str, timeout: float = 8.0) -> str:
    url = normalize_url(target)
    res = httpx.get(url, timeout=timeout, follow_redirects=True, verify=False)
    return res.text


def extract_links(html: str, base_url: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    base_host = urlparse(base_url).netloc
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"]
        full_url = urljoin(base_url, href)
        if urlparse(full_url).netloc == base_host:
            links.append(full_url)
    return list(dict.fromkeys(links))


def extract_forms(html: str, base_url: str) -> List[Dict[str, Optional[str]]]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "get").lower()
        enctype = (form.get("enctype") or "").lower()
        inputs = [tag.get("name") for tag in form.find_all(["input", "textarea"]) if tag.get("name")]
        file_inputs = bool(form.find("input", {"type": "file"})) or "multipart" in enctype
        forms.append({
            "action": urljoin(base_url, action),
            "method": method,
            "enctype": enctype,
            "inputs": inputs,
            "file_upload": file_inputs,
        })
    return forms


def build_query_url(base_url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(base_url)
    query = urlencode(params)
    return parsed._replace(query=query).geturl()  # type: ignore


def extract_query_params(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    return dict(parse_qsl(parsed.query, keep_blank_values=True))
