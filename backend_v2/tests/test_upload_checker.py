def test_upload_checker_detects_retrievable_upload(monkeypatch):
    from backend_v2.tools.upload_checker import upload_checker

    class DummyResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code

    def fake_get(url, timeout, follow_redirects, verify):
        if url == "http://example.com/page":
            return DummyResponse(
                '<form action="/upload" enctype="multipart/form-data"><input type="file" name="file" /></form>'
            )
        if url == "http://example.com/upload/uploads/portbiter_test.txt":
            return DummyResponse("PortBiter upload test payload", status_code=200)
        return DummyResponse("", status_code=404)

    def fake_post(url, files, timeout, follow_redirects, verify):
        return DummyResponse(
            "File saved at /uploads/portbiter_test.txt",
            status_code=201,
        )

    monkeypatch.setattr("backend_v2.tools.upload_checker.httpx.get", fake_get)
    monkeypatch.setattr("backend_v2.tools.upload_checker.httpx.post", fake_post)

    result = upload_checker.func("http://example.com/page")
    assert "UPLOAD VULNERABILITY" in result
    assert "/uploads/portbiter_test.txt" in result
