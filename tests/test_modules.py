import httpx

from rieazuka.modules import audit_cookies, audit_headers, audit_tech


def response(headers=None, url="https://example.test/"):
    request = httpx.Request("GET", url)
    return httpx.Response(200, headers=headers or {}, request=request)


def test_missing_headers_are_reported():
    findings = audit_headers(response())
    titles = {f.title for f in findings}
    assert "Content-Security-Policy is missing" in titles
    assert "HSTS is missing" in titles


def test_good_cookie_flags():
    findings = audit_cookies(response({"set-cookie": "session=x; Secure; HttpOnly; SameSite=Lax"}))
    assert findings == []


def test_cookie_issues():
    findings = audit_cookies(response({"set-cookie": "session=x"}))
    assert len(findings) == 3


def test_technology_disclosure():
    findings = audit_tech(response({"server": "example-server"}))
    assert findings[0].evidence == "example-server"
