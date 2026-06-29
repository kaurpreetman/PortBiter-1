import httpx
from langchain_core.tools import tool
from backend_v2.tools.recon_helper import fetch_html, extract_forms, normalize_url, extract_links


@tool
def xss_tester(target: str) -> str:
    """Tests a target URL for reflected XSS by probing query params and form inputs."""
    probe = "<script>portbiter_xss_test</script>"
    try:
        target_url = normalize_url(target)
        text = fetch_html(target_url)
        links = [target_url] + extract_links(text, target_url)

        for link in links[:5]:
            res = httpx.get(link, timeout=8.0, follow_redirects=True, verify=False)
            if probe in res.text:
                return f"XSS FOUND: reflected payload in response body at {link}"

            forms = extract_forms(res.text, link)
            for form in forms:
                if not form["inputs"]:
                    continue
                data = {name: probe for name in form["inputs"]}
                method = form["method"]
                if method == "post":
                    form_res = httpx.post(form["action"], data=data, timeout=8.0, follow_redirects=True, verify=False)
                else:
                    form_res = httpx.get(form["action"], params=data, timeout=8.0, follow_redirects=True, verify=False)
                if probe in form_res.text:
                    return f"XSS FOUND: reflected form input at {form['action']}"

        return f"No XSS vulnerabilities found on {target_url}"
    except Exception as exc:
        return f"XSS tester error: {exc}"
