from pathlib import Path

import pytest

from rieazuka.core import Finding, ScanResult, ScopeError, Severity, host_in_scope, validate_scope
from rieazuka.reporting import write_html


def test_exact_scope():
    assert host_in_scope("example.test", "example.test")
    assert not host_in_scope("evil.example.test", "example.test")


def test_localhost_does_not_require_ack():
    assert validate_scope("http://localhost:8000", "localhost", False) == "localhost"


def test_remote_requires_ack():
    with pytest.raises(ScopeError):
        validate_scope("https://example.test", "example.test", False)


def test_outside_scope_rejected():
    with pytest.raises(ScopeError):
        validate_scope("https://other.test", "example.test", True)


def test_html_escapes_evidence(tmp_path: Path):
    result = ScanResult("http://localhost", [Finding("test", "x", Severity.INFO, "desc", "<script>alert(1)</script>")])
    path = tmp_path / "report.html"
    write_html(result, str(path))
    content = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content
