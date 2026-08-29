from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx

from .core import Finding, ScanResult, host_in_scope, validate_scope
from .modules import audit_cookies, audit_cors, audit_discovery, audit_headers, audit_tech, audit_tls


AVAILABLE_MODULES = ("headers", "cookies", "cors", "tls", "tech", "security-txt", "robots")


async def scan(target: str, scope: str, ack_authorized: bool, modules: list[str], timeout: float = 8.0) -> ScanResult:
    validate_scope(target, scope, ack_authorized)
    unknown = sorted(set(modules) - set(AVAILABLE_MODULES))
    if unknown:
        raise ValueError(f"Unknown modules: {', '.join(unknown)}")

    result = ScanResult(target=target)
    limits = httpx.Limits(max_connections=2, max_keepalive_connections=1)
    headers = {"User-Agent": "RieaZuka/1.0 (+authorized-security-audit)"}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, limits=limits, headers=headers) as client:
        try:
            response = await client.get(target)
        except httpx.HTTPError as exc:
            result.errors.append(f"Initial request failed: {exc}")
            return result

        if response.is_redirect:
            location = response.headers.get("location")
            if location:
                redirected = str(response.url.join(location))
                redirected_host = urlparse(redirected).hostname or ""
                if not host_in_scope(redirected_host, scope):
                    result.errors.append(f"Redirect blocked because it leaves scope: {redirected_host}")
                    return result
                try:
                    response = await client.get(redirected)
                except httpx.HTTPError as exc:
                    result.errors.append(f"Redirect request failed: {exc}")
                    return result

        if "headers" in modules:
            result.findings.extend(audit_headers(response))
        if "cookies" in modules:
            result.findings.extend(audit_cookies(response))
        if "tech" in modules:
            result.findings.extend(audit_tech(response))
        if "cors" in modules:
            await asyncio.sleep(0.15)
            result.findings.extend(await audit_cors(client, str(response.url)))
        if "security-txt" in modules:
            await asyncio.sleep(0.15)
            result.findings.extend(await audit_discovery(client, str(response.url), "security-txt"))
        if "robots" in modules:
            await asyncio.sleep(0.15)
            result.findings.extend(await audit_discovery(client, str(response.url), "robots"))
        if "tls" in modules:
            result.findings.extend(await asyncio.to_thread(audit_tls, str(response.url), min(timeout, 5.0)))

    return result
