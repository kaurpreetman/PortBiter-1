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
            found_form = False
            for form in soup.find_all("form"):
                action = form.get("action") or target
                enctype = (form.get("enctype") or "").lower()
                if "multipart" in enctype or form.find("input", {"type": "file"}):
                    upload_url = urljoin(target, action)
                    found_form = True
                    break

            if not found_form:
                return f"No upload form found on {target}"

        file_name = "portbiter_test.txt"
        payload = b"PortBiter upload test payload"
        files = {"file": (file_name, payload, "text/plain")}
        res = httpx.post(upload_url, files=files, timeout=8.0, follow_redirects=True, verify=False)
        body = res.text.lower()

        if res.status_code not in {200, 201, 202, 204} or any(marker in body for marker in ["invalid", "rejected", "not allowed", "error", "forbidden", "denied"]):
            return f"No upload vulnerability detected at {upload_url}"

        uploaded_url = None
        if file_name in res.text:
            for token in res.text.split():
                cleaned = token.strip('"\'<>.,')
                if file_name in cleaned:
                    if cleaned.startswith("http"):
                        uploaded_url = cleaned
                        break
                    if "/" in cleaned:
                        uploaded_url = urljoin(upload_url, cleaned)
                        break

        if not uploaded_url:
            common_dirs = ["uploads/", "upload/", "files/", "media/"]
            for dir_path in common_dirs:
                candidate = urljoin(upload_url, dir_path + file_name)
                verify_res = httpx.get(candidate, timeout=8.0, follow_redirects=True, verify=False)
                if verify_res.status_code == 200 and payload.decode() in verify_res.text:
                    uploaded_url = candidate
                    break

        if uploaded_url:
            return (
                f"UPLOAD VULNERABILITY: Server accepted a test upload at {upload_url} "
                f"and the file was retrievable at {uploaded_url}."
            )

        return (
            f"UPLOAD WARNING: Server accepted a test upload at {upload_url}, "
            "but the uploaded file location could not be verified. Manual follow-up required."
        )
    except Exception as exc:
        return f"Upload checker error: {exc}"
