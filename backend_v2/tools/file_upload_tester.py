import httpx
from langchain_core.tools import tool
from backend_v2.tools.recon_helper import fetch_html, extract_forms, normalize_url


@tool
def file_upload_tester(target: str) -> str:
    """Looks for upload-capable forms and verifies whether file upload endpoints are reachable."""
    try:
        target_url = normalize_url(target)
        html = fetch_html(target_url)
        forms = extract_forms(html, target_url)
        upload_forms = [form for form in forms if form.get("file_upload")]

        if not upload_forms:
            return f"No file upload forms detected on {target_url}"

        for form in upload_forms:
            response = httpx.options(form["action"], timeout=8.0, follow_redirects=True, verify=False)
            if response.status_code < 400:
                return f"FILE UPLOAD ENDPOINT: {form['action']} appears reachable and may accept uploads"

        return f"Upload forms found, but endpoints were not reachable on {target_url}"
    except Exception as exc:
        return f"File upload tester error: {exc}"
