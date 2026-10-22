"""HTTP qatı testləri: autentifikasiya, parametr validasiyası, təhlükəsizlik header-ləri, UI."""

import pytest
from fastapi.testclient import TestClient

from src.api.app import CSP, create_app
from src.api.service import IndexerUnavailable
from src.config.config import ApiSettings, Settings


class FakeService:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def overview(self, minutes, source, limit):
        self.calls.append((minutes, source, limit))
        if self.fail:
            raise IndexerUnavailable("Indexer-ə qoşulmaq olmadı: test")
        return {"meta": {"truncated": False}, "summary": {"total": 1}, "events": [
            {"event_name": "LinuxLoginFailure", "user": "<script>alert(1)</script>", "raw": {}}]}

    def check_indexer(self):
        return {"ok": not self.fail, "version": "2.x"}


def client(password="", fail=False):
    settings = Settings(api=ApiSettings(basic_user="admin", basic_password=password))
    svc = FakeService(fail=fail)
    return TestClient(create_app(service=svc, settings=settings)), svc


def test_healthz_is_open_even_with_auth():
    c, _ = client(password="s3cret")
    r = c.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/", "/api/overview", "/api/health", "/ui/app.js", "/ui/app.css"])
def test_auth_required_when_password_set(path):
    c, _ = client(password="s3cret")
    r = c.get(path)
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Basic")
    assert c.get(path, auth=("admin", "wrong")).status_code == 401
    assert c.get(path, auth=("root", "s3cret")).status_code == 401
    assert c.get(path, auth=("admin", "s3cret")).status_code == 200


def test_no_auth_when_password_empty():
    c, _ = client(password="")
    assert c.get("/api/overview").status_code == 200


def test_overview_passes_params_and_validates():
    c, svc = client()
    assert c.get("/api/overview?minutes=120&source=linux&limit=50").status_code == 200
    assert svc.calls[-1] == (120, "linux", 50)
    assert c.get("/api/overview").status_code == 200 and svc.calls[-1] == (60, "all", 200)
    for bad in ("minutes=1", "minutes=99999", "source=mainframe", "limit=0", "limit=5000", "minutes=abc"):
        assert c.get(f"/api/overview?{bad}").status_code == 422, bad


def test_indexer_failure_is_502_with_safe_message():
    c, _ = client(fail=True)
    r = c.get("/api/overview")
    assert r.status_code == 502 and "qoşulmaq" in r.json()["detail"]
    h = c.get("/api/health").json()
    assert h["status"] == "degraded"


def test_security_headers_and_no_store():
    c, _ = client()
    r = c.get("/api/overview")
    assert r.headers["content-security-policy"] == CSP
    assert "script-src 'self'" in CSP and "unsafe-inline" not in CSP
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_ui_served_and_asset_whitelist():
    c, _ = client()
    idx = c.get("/")
    assert idx.status_code == 200 and "text/html" in idx.headers["content-type"]
    assert "/ui/app.js" in idx.text and "<script>" not in idx.text   # inline skript yoxdur
    assert c.get("/ui/app.js").headers["content-type"].startswith("text/javascript")
    assert c.get("/ui/app.css").headers["content-type"].startswith("text/css")
    for name in ("index.html", "..%2f..%2fconfig.py", "../app.py", "secret.txt"):
        assert c.get(f"/ui/{name}").status_code == 404, name


def test_docs_endpoints_disabled():
    c, _ = client()
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(p).status_code == 404
