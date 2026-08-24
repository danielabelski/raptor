"""Web cache poisoning and cache deception -- Kettle methodology.

Web cache poisoning: inject unkeyed input that the app reflects into a
cached response, delivering malicious content to every subsequent visitor.

Web cache deception: trick the cache into storing an authenticated response
under a path that maps to a cache rule for static files, making it publicly
readable.

Reference: James Kettle, PortSwigger Research
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from packages.web.checks.base import PROBE_HOST, Check, CheckCategory, registry

if TYPE_CHECKING:
    pass

_UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Scheme",
]

_CACHE_INDICATORS = {
    "X-Cache", "CF-Cache-Status", "X-Cache-Hit", "X-Varnish",
    "Age", "Via", "X-Drupal-Cache", "X-Proxy-Cache",
}

_PROBE_VALUE = PROBE_HOST


def _is_cached(headers: dict) -> bool:
    for indicator in _CACHE_INDICATORS:
        val = headers.get(indicator, "")
        if val:
            return True
    return False


@registry.register(CheckCategory.INJECTION, "V5.1.12", "Web cache poisoning via unkeyed headers")
class CachePoisoningCheck(Check):
    risk = "active"
    def run(self, client, target_url, session=None, discovery=None):
        # First check if there is a cache at all
        try:
            baseline = client.get("/")
        except Exception:
            return []

        if not _is_cached(baseline.headers):
            return []

        findings = []

        for header in _UNKEYED_HEADERS:
            try:
                resp = client.get("/", headers={header: _PROBE_VALUE})
                body = resp.text if isinstance(resp.text, str) else ""

                if _PROBE_VALUE in body:
                    # Is the response still cached?
                    cache_status = resp.headers.get("X-Cache", "") or resp.headers.get("CF-Cache-Status", "")
                    findings.append(self._result(
                        passed=False, url=target_url,
                        evidence=(
                            f"{header}: {_PROBE_VALUE} "
                            f"reflected in cached response "
                            f"(cache status: {cache_status!r})"
                        ),
                        detail=(
                            f"The '{header}' header value is reflected in the application "
                            f"response and the response appears to be served from a cache. "
                            f"If this header is unkeyed (not part of the cache key), an attacker "
                            f"can poison the cache to deliver a malicious response to every user "
                            f"who subsequently requests this URL -- enabling stored XSS at scale, "
                            f"credential theft, or session fixation for all visitors."
                        ),
                        recommendation=(
                            "Add all headers that influence the response to the cache key. "
                            "Configure the CDN/reverse proxy to normalise or strip unrecognised "
                            "headers before they reach the application. "
                            "Validate the Host header against an allowlist."
                        ),
                        severity="critical", asvs_ref="ASVS 5.0 V5.1.12",
                    ))
                    break

            except Exception:
                continue

        return findings


@registry.register(CheckCategory.INJECTION, "V5.1.13", "Web cache deception risk")
class CacheDeceptionCheck(Check):
    risk = "active"
    def run(self, client, target_url, session=None, discovery=None):
        if not session or not session.authenticated:
            return []

        # Look for profile/account pages in discovery
        sensitive_paths = ["/account", "/profile", "/settings", "/dashboard", "/me"]
        if discovery:
            for url in discovery.get("urls", []):
                from urllib.parse import urlparse
                path = urlparse(url).path.lower()
                if any(k in path for k in ("account", "profile", "settings", "dashboard")):
                    sensitive_paths.insert(0, urlparse(url).path)

        for path in sensitive_paths[:3]:
            try:
                # Try appending a static-file suffix to a sensitive path
                deception_path = path.rstrip("/") + "/nonexistent.css"
                resp = client.get(deception_path)

                if resp.status_code == 200:
                    # Check if the response contains profile/account data
                    body = resp.text if isinstance(resp.text, str) else ""
                    has_user_data = any(
                        kw in body.lower()
                        for kw in ("email", "username", "account", "profile", "address")
                    )

                    if has_user_data and _is_cached(resp.headers):
                        return [self._result(
                            passed=False, url=target_url.rstrip("/") + deception_path,
                            evidence=(
                                f"GET {deception_path} returned HTTP 200 with apparent user data "
                                f"and cache indicators present"
                            ),
                            detail=(
                                f"The application returns authenticated account data for '{path}' "
                                f"even when a static-file suffix is appended ({deception_path}). "
                                f"If the caching layer matches on file extension and caches this "
                                f"response, unauthenticated users can access cached copies of "
                                f"other users' account pages simply by requesting the same URL "
                                f"after the victim visited it."
                            ),
                            recommendation=(
                                "Configure the application to return 404 for paths it doesn't "
                                "recognise rather than falling back to a parent route. "
                                "Ensure the CDN never caches responses that contain "
                                "Cache-Control: private or that require authentication."
                            ),
                            severity="high", asvs_ref="ASVS 5.0 V5.1.13",
                        )]
            except Exception:
                continue

        return []


@registry.register(CheckCategory.INJECTION, "V5.1.14", "HTTP request smuggling probe (CL.TE)")
class RequestSmugglingCheck(Check):
    risk = "active"

    # Desync-prerequisite probes, one per parser-disagreement class.
    # Each is a heuristic ("both framing headers processed" /
    # "body interpreted as a second request"), never a confirmed
    # verdict — findings stay confidence=low with a manual-follow-up
    # instruction, matching the original CL.TE behavior.
    @staticmethod
    def _probe_requests(host: str) -> list[tuple[str, str, str]]:
        clte = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )
        # Front-end honors Transfer-Encoding (reads the full chunked
        # body); a CL back-end stops after 3 bytes and parses the rest
        # as the start of a new request.
        tecl = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"8\r\n"
            f"SMUGGLED\r\n"
            f"0\r\n"
            f"\r\n"
        )
        # A CL.0 back-end ignores Content-Length entirely: the body
        # arrives as a SECOND request on the same connection, so two
        # responses come back for one send.
        prefix = (
            f"GET /raptor-clzero-probe HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"\r\n"
        )
        clzero = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(prefix)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{prefix}"
        )
        return [
            ("CL.TE", clte, "fast_400"),
            ("TE.CL", tecl, "fast_400"),
            ("CL.0", clzero, "double_response"),
        ]

    def run(self, client, target_url, session=None, discovery=None):
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"

        for variant, request_text, signal in self._probe_requests(host):
            response, duration = self._raw_exchange(
                host, port, use_tls, request_text,
            )
            if response is None:
                continue
            hit = (
                signal == "fast_400"
                and "400" in response and duration < 1
            ) or (
                signal == "double_response"
                and response.count("HTTP/1.") >= 2
            )
            if not hit:
                continue
            return [self._result(
                passed=False, url=target_url,
                evidence=(
                    f"{variant} probe: "
                    + (
                        f"server returned 400 in {duration:.2f}s -- "
                        "possible back-end desync."
                        if signal == "fast_400" else
                        "two HTTP responses returned for one request -- "
                        "the body was parsed as a second request."
                    )
                    + " Manual verification required."
                ),
                detail=(
                    f"The server's framing behavior is consistent with the "
                    f"{variant} HTTP request smuggling prerequisite: the "
                    "front-end and back-end disagree about where one "
                    "request ends and the next begins. A successful "
                    "smuggling attack allows bypassing front-end security "
                    "controls, poisoning other users' requests, and "
                    "stealing credentials from other sessions. Manual "
                    "verification with Burp Suite HTTP Request Smuggler "
                    "is strongly recommended."
                ),
                recommendation=(
                    "Configure the front-end proxy to normalise "
                    "Transfer-Encoding headers and reject requests with "
                    "both Content-Length and Transfer-Encoding. "
                    "Use HTTP/2 end-to-end where possible. "
                    "Apply the same header handling rules on every hop "
                    "in the proxy chain."
                ),
                severity="high", confidence="low",
                asvs_ref="ASVS 5.0 V5.1.14",
            )]

        return []

    @staticmethod
    def _raw_exchange(
        host: str, port: int, use_tls: bool, request_text: str,
    ) -> tuple:
        """One raw request/response exchange; (None, 0.0) on error."""
        import socket
        import ssl
        import time

        try:
            sock = socket.create_connection((host, port), timeout=5)
            if use_tls:
                ctx = ssl.create_default_context()
                # Scanner semantics, not client semantics: this raw
                # probe exists to elicit a parsing differential from
                # whatever stack the TARGET runs, legacy included —
                # transport privacy is not a goal and there is nothing
                # of ours to protect. Pin the floor explicitly instead
                # of inheriting build defaults; TLS 1.0 is deliberate
                # (distro OpenSSL policy may still refuse below 1.2 at
                # handshake time, which only narrows reach).
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(request_text.encode())
            t_start = time.monotonic()
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
            duration = time.monotonic() - t_start
            sock.close()
            return data.decode("utf-8", errors="replace"), duration
        except Exception:
            return None, 0.0
