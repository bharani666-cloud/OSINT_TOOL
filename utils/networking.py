"""
Shared HTTP session + benign socket helpers.

- Every request has a timeout.
- A simple token-bucket-free delay-based rate limiter is applied between
  requests to the same host, to be a good citizen of third-party APIs.
- Redirects to a different host than requested are NOT followed
  automatically (we resolve manually and refuse cross-host redirects),
  matching the "do not follow suspicious redirects" requirement.
"""

from __future__ import annotations

import socket
import time
from typing import Any, Optional
from urllib.parse import urlparse

import requests

from config import SETTINGS

_LAST_REQUEST_TIME: dict[str, float] = {}

USER_AGENT = "AuthorizedOSINTTool/1.0 (+lawful-investigation-use-only)"


def _throttle(host: str) -> None:
    now = time.monotonic()
    last = _LAST_REQUEST_TIME.get(host, 0.0)
    wait = SETTINGS.rate_limit_delay - (now - last)
    if wait > 0:
        time.sleep(wait)
    _LAST_REQUEST_TIME[host] = time.monotonic()


def safe_get(
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    params: Optional[dict[str, Any]] = None,
    timeout: Optional[float] = None,
) -> requests.Response:
    """
    A GET wrapper that enforces a timeout, rate limiting per host, and
    refuses to auto-follow a redirect to a different host (to avoid
    silently being routed somewhere unexpected).
    """
    parsed = urlparse(url)
    _throttle(parsed.netloc)

    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)

    response = requests.get(
        url,
        headers=req_headers,
        params=params,
        timeout=timeout or SETTINGS.request_timeout,
        allow_redirects=False,
    )

    # Manually resolve same-host redirects only (max 3 hops), refuse cross-host.
    hops = 0
    while response.is_redirect and hops < 3:
        location = response.headers.get("Location", "")
        if not location:
            break
        next_parsed = urlparse(location)
        if next_parsed.netloc and next_parsed.netloc != parsed.netloc:
            # Cross-host redirect: stop here rather than following blindly.
            break
        _throttle(next_parsed.netloc or parsed.netloc)
        response = requests.get(
            location,
            headers=req_headers,
            timeout=timeout or SETTINGS.request_timeout,
            allow_redirects=False,
        )
        hops += 1

    return response


def resolve_hostname(hostname: str) -> list[str]:
    """Benign DNS resolution only -- no scanning."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def reverse_dns(ip: str) -> Optional[str]:
    """Benign reverse DNS lookup only."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def hostname_resolves(hostname: str) -> bool:
    return len(resolve_hostname(hostname)) > 0
