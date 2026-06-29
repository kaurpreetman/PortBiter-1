from backend_v2.tools.recon_helper import extract_forms, normalize_url


def test_normalize_url_adds_scheme():
    assert normalize_url("example.com") == "http://example.com"
    assert normalize_url("https://example.com") == "https://example.com"


def test_extract_forms_detects_file_upload():
    html = '<form action="/upload" method="post" enctype="multipart/form-data"><input type="file" name="file" /></form>'
    forms = extract_forms(html, "http://example.com")
    assert len(forms) == 1
    assert forms[0]["file_upload"] is True
    assert forms[0]["action"] == "http://example.com/upload"
