from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup
from langchain_core.tools import tool


@tool
def xss_scanner(target: str) -> str:
    """Tests a target URL for reflected XSS by probing query parameters and form inputs."""
    probe = "<script>portbiter_xss_test</script>"
    findings = []

    try:
        parsed = urlparse(target)
        if not parsed.scheme:
            target = f"http://{target}"
            parsed = urlparse(target)

        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        parameter_names = list(query.keys()) or ["q"]
        for name in parameter_names:
            updated = query.copy()
            updated[name] = probe
            new_query = urlencode(updated)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            res = httpx.get(test_url, timeout=8.0, follow_redirects=True, verify=False)
            if probe in res.text:
                findings.append(f"XSS FOUND: reflected query parameter '{name}' at {test_url}")

        if not findings:
            response = httpx.get(target, timeout=8.0, follow_redirects=True, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action") or target
                method = (form.get("method") or "get").lower()
                inputs = [tag.get("name") for tag in form.find_all(["input", "textarea"]) if tag.get("name")]
                if not inputs:
                    continue
                data = {name: probe for name in inputs}
                if method == "post":
                    form_res = httpx.post(action, data=data, timeout=8.0, follow_redirects=True, verify=False)
                else:
                    form_res = httpx.get(action, params=data, timeout=8.0, follow_redirects=True, verify=False)
                if probe in form_res.text:
                    findings.append(f"XSS FOUND: reflected form input at {action}")

        if findings:
            return "\n".join(findings)

        return f"No XSS vulnerabilities found on {target}"
    except Exception as exc:
        return f"XSS scanner error: {exc}"
