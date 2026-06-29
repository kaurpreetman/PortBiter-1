import httpx
from bs4 import BeautifulSoup
from langchain_core.tools import tool
from urllib.parse import urljoin


@tool
def upload_checker(target: str) -> str:
    """Tests a target URL for unrestricted file upload behavior using safe test files."""
    try:
        upload_url = target
        if "upload" not in target.lower():
            response = httpx.get(target, timeout=8.0, follow_redirects=True, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action") or target
                enctype = (form.get("enctype") or "").lower()
                if "multipart" in enctype or any(tag.get("type") == "file" for tag in form.find_all(["input", "textarea"])):
                    upload_url = urljoin(target, action)
                    break

        files = {"file": ("test.txt", b"portbiter_upload_test", "text/plain")}
        res = httpx.post(upload_url, files=files, timeout=8.0, follow_redirects=True, verify=False)
        body = res.text.lower()
        if res.status_code in {200, 201, 202, 204} and not any(marker in body for marker in ["invalid", "rejected", "not allowed", "error"]):
            return f"UPLOAD VULNERABILITY: Server accepted a test file upload at {upload_url} without visible validation"

        php_files = {"file": ("test.php", b"<?php echo 'portbiter'; ?>", "application/octet-stream")}
        php_res = httpx.post(upload_url, files=php_files, timeout=8.0, follow_redirects=True, verify=False)
        php_body = php_res.text.lower()
        if php_res.status_code in {200, 201, 202, 204} and not any(marker in php_body for marker in ["invalid", "rejected", "not allowed", "error"]):
            return f"UPLOAD VULNERABILITY: Server accepted a PHP-style upload at {upload_url} - potential arbitrary file upload"

        return f"No upload vulnerability detected at {upload_url}"
    except Exception as exc:
        return f"Upload checker error: {exc}"
