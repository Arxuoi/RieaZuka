from __future__ import annotations

from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urljoin, urlparse

import httpx

from .core import Finding, Severity


SECURITY_HEADERS = {
    "content-security-policy": (Severity.MEDIUM, "Content-Security-Policy is missing"),
    "x-content-type-options": (Severity.LOW, "X-Content-Type-Options is missing"),
    "referrer-policy": (Severity.LOW, "Referrer-Policy is missing"),
    "permissions-policy": (Severity.LOW, "Permissions-Policy is missing"),
}


def audit_headers(response: httpx.Response) -> list[Finding]:
    findings: list[Finding] = []
    headers = response.headers
    for name, (severity, title) in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append(Finding("headers", title, severity, f"Response does not set {name}.", remediation=f"Set an appropriate {name} header."))
    if response.url.scheme == "https" and "strict-transport-security" not in headers:
        findings.append(Finding("headers", "HSTS is missing", Severity.MEDIUM, "HTTPS response does not set Strict-Transport-Security.", remediation="Enable HSTS after confirming the site is HTTPS-only."))
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
        findings.append(Finding("headers", "Clickjacking protection not detected", Severity.LOW, "Neither X-Frame-Options nor CSP frame-ancestors was detected.", remediation="Use CSP frame-ancestors or X-Frame-Options."))
    return findings


def audit_cookies(response: httpx.Response) -> list[Finding]:
    findings: list[Finding] = []
    for raw in response.headers.get_list("set-cookie"):
        first = raw.split(";", 1)[0]
        name = first.split("=", 1)[0].strip() or "cookie"
        lower = raw.lower()
        if response.url.scheme == "https" and "; secure" not in lower:
            findings.append(Finding("cookies", f"Cookie {name} lacks Secure", Severity.MEDIUM, "Cookie may be sent over an unencrypted connection.", evidence=name, remediation="Add the Secure attribute."))
        if "; httponly" not in lower:
            findings.append(Finding("cookies", f"Cookie {name} lacks HttpOnly", Severity.LOW, "Cookie is accessible to client-side scripts.", evidence=name, remediation="Add HttpOnly when JavaScript access is unnecessary."))
        if "samesite=" not in lower:
            findings.append(Finding("cookies", f"Cookie {name} lacks SameSite", Severity.LOW, "No explicit SameSite policy was detected.", evidence=name, remediation="Set SameSite=Lax or Strict when compatible."))
    return findings


def audit_tech(response: httpx.Response) -> list[Finding]:
    findings: list[Finding] = []
    for header in ("server", "x-powered-by"):
        if header in response.headers:
            findings.append(Finding("tech", f"Technology disclosure via {header}", Severity.INFO, "Response exposes implementation information.", evidence=response.headers[header], remediation="Remove unnecessary version or implementation disclosure."))
    return findings


async def audit_cors(client: httpx.AsyncClient, target: str) -> list[Finding]:
    benign_origin = "https://rieazuka.invalid"
    try:
        response = await client.get(target, headers={"Origin": benign_origin})
    except httpx.HTTPError as exc:
        return [Finding("cors", "CORS check failed", Severity.INFO, str(exc))]
    allow_origin = response.headers.get("access-control-allow-origin", "")
    credentials = response.headers.get("access-control-allow-credentials", "").lower() == "true"
    findings: list[Finding] = []
    if allow_origin == "*" and credentials:
        findings.append(Finding("cors", "Inconsistent permissive CORS policy", Severity.MEDIUM, "Wildcard origin and credentials were both advertised.", evidence="Access-Control-Allow-Origin: *; credentials: true", remediation="Use a strict allowlist and avoid credentialed wildcard policies."))
    elif allow_origin == benign_origin and credentials:
        findings.append(Finding("cors", "Arbitrary Origin appears trusted with credentials", Severity.HIGH, "The server reflected a benign untrusted Origin while allowing credentials.", evidence=f"Access-Control-Allow-Origin: {allow_origin}", remediation="Validate Origin against a strict allowlist."))
    elif allow_origin == benign_origin:
        findings.append(Finding("cors", "Origin reflection detected", Severity.LOW, "The server reflected an arbitrary benign Origin.", evidence=f"Access-Control-Allow-Origin: {allow_origin}", remediation="Use an explicit allowlist if cross-origin access is not intended."))
    return findings


async def audit_discovery(client: httpx.AsyncClient, target: str, item: str) -> list[Finding]:
    path = "/.well-known/security.txt" if item == "security-txt" else "/robots.txt"
    url = urljoin(target, path)
    try:
        response = await client.get(url)
    except httpx.HTTPError as exc:
        return [Finding(item, f"{path} check failed", Severity.INFO, str(exc))]
    if response.status_code == 200:
        return [Finding(item, f"{path} discovered", Severity.INFO, "The metadata file is publicly available.", evidence=f"HTTP {response.status_code}")]
    if item == "security-txt":
        return [Finding(item, "security.txt not detected", Severity.INFO, "No security.txt was found at the standard location.", evidence=f"HTTP {response.status_code}", remediation="Consider publishing /.well-known/security.txt for vulnerability disclosure contacts.")]
    return []


def audit_tls(target: str, timeout: float = 5.0) -> list[Finding]:
    parsed = urlparse(target)
    if parsed.scheme != "https" or not parsed.hostname:
        return []
    host = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    findings: list[Finding] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                protocol = sock.version() or "unknown"
                cipher = sock.cipher()
                findings.append(Finding("tls", "TLS connection metadata", Severity.INFO, "Negotiated TLS connection details.", evidence=f"protocol={protocol}; cipher={cipher[0] if cipher else 'unknown'}"))
                expires = cert.get("notAfter")
                if expires:
                    expiry = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days = (expiry - datetime.now(timezone.utc)).days
                    if days < 0:
                        findings.append(Finding("tls", "TLS certificate expired", Severity.HIGH, "The certificate is expired.", evidence=f"expired {expires}", remediation="Renew and deploy a valid certificate."))
                    elif days < 30:
                        findings.append(Finding("tls", "TLS certificate expires soon", Severity.MEDIUM, "The certificate expires within 30 days.", evidence=f"expires {expires}", remediation="Renew the certificate before expiration."))
    except (OSError, ssl.SSLError, ValueError) as exc:
        findings.append(Finding("tls", "TLS inspection failed", Severity.INFO, str(exc)))
    return findings
