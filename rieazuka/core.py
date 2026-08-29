from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import ipaddress
from urllib.parse import urlparse


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(slots=True)
class Finding:
    module: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(slots=True)
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
        }


class ScopeError(ValueError):
    pass


def normalize_target(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("Target must be an http:// or https:// URL with a hostname")
    if parsed.username or parsed.password:
        raise ScopeError("Credentials in target URLs are not supported")
    return value


def is_local_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def host_in_scope(host: str, scope: str) -> bool:
    host = host.lower().rstrip(".")
    scope = scope.lower().rstrip(".")
    return host == scope


def validate_scope(target: str, scope: str, ack_authorized: bool) -> str:
    normalize_target(target)
    parsed = urlparse(target)
    host = parsed.hostname or ""
    if not scope:
        raise ScopeError("An explicit --scope hostname is required")
    if not host_in_scope(host, scope):
        raise ScopeError(f"Target host {host!r} is outside declared scope {scope!r}")
    if not is_local_host(host) and not ack_authorized:
        raise ScopeError("Non-local targets require --ack-authorized")
    return host
