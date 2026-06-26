"""Small utilities shared across the package.

Kept intentionally minimal. Anything non-trivial should live in its own
module (``models``, ``extractors``, ...).
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Iterable
from urllib.parse import urlparse, urlunparse

# Pre-compiled for hot-path speed
_WHITESPACE_RE = re.compile(r"\s+")
_NON_ALPHA_RE = re.compile(r"[^a-z\s]")
# Strip ASCII control chars except whitespace (tab, newline, CR). Used
# by sanitize_text() to clean externally-sourced content before it
# reaches the LLM context.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]")


def normalize_url(url: str) -> str:
    """Strip query string and trailing slash, lowercase, for dedup."""
    if not url:
        return ""
    return url.split("?", 1)[0].rstrip("/").lower()


def host_of(url: str) -> str:
    """Extract the lowercased hostname from a URL, or empty string on error."""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def filter_by_domain(
    results: Iterable[dict],
    allowed: tuple = (),
    blocked: tuple = (),
) -> list:
    """Filter a sequence of result dicts by allowed/blocked host lists.

    Args:
        results: Iterable of dicts with a ``"url"`` key.
        allowed: If non-empty, only hosts in this tuple are kept.
        blocked: Hosts in this tuple are dropped.

    Returns:
        A new list preserving order. Results without a parsable host are
        dropped because they cannot be safely evaluated against the
        allow/block policy and would otherwise bypass it.
    """
    allowed_set = {d.lower() for d in allowed} if allowed else set()
    blocked_set = {d.lower() for d in blocked} if blocked else set()
    out = []
    for r in results:
        url = r.get("url", "")
        host = host_of(url)
        if not host:
            # URLs without a parsable host (e.g. relative or malformed)
            # are dropped by default. They cannot be safely fetched
            # downstream and would bypass any allow/block policy.
            continue
        if allowed_set and host not in allowed_set:
            continue
        if blocked_set and host in blocked_set:
            continue
        out.append(r)
    return out


def deduplicate(results: Iterable[dict]) -> list:
    """Remove duplicate URLs from a list of result dicts, preserving order."""
    seen: set = set()
    out: list = []
    for r in results:
        key = normalize_url(r.get("url", ""))
        if key and key not in seen:
            seen.add(key)
            out.append(r)
    return out


def chunk_text(text: str, max_chars: int) -> list:
    """Split ``text`` into chunks of at most ``max_chars`` characters.

    Tries to break on whitespace when possible.
    """
    if max_chars <= 0 or not text:
        return [text] if text else []
    chunks = []
    i = 0
    n = len(text)
    while i < n:
        end = min(i + max_chars, n)
        if end < n:
            # Walk back to the last whitespace before the cutoff
            j = text.rfind(" ", i, end)
            if j > i:
                end = j
        chunks.append(text[i:end].strip())
        i = end
    return [c for c in chunks if c]


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------


def is_internal_ip(ip_str: str) -> bool:
    """Return True if an IP address is private, loopback, link-local,
    multicast, reserved, or unspecified.

    Also flags IPv4-mapped IPv6 addresses (e.g. ``::ffff:127.0.0.1``) by
    re-checking the embedded IPv4 representation. The IPv6 properties
    (``is_private``/``is_loopback``/...) do not see the IPv4 suffix, so
    a naive check would let ``http://[::ffff:127.0.0.1]/`` reach a
    loopback target.

    Unparseable strings are treated as internal (deny by default) so a
    malformed IP cannot accidentally pass an SSRF guard. When in doubt,
    refuse.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return True
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    # IPv4-mapped IPv6 (::ffff:0:0/96): v6 properties miss the embedded
    # v4. Re-validate the v4 form. ``ipv4_mapped`` is None when the
    # address is not in the mapped range, so the branch is safe.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return is_internal_ip(str(ip.ipv4_mapped))
    return False


def is_safe_url(url: str) -> bool:
    """Return True if ``url`` looks safe to fetch.

    Fast, dependency-free pre-check. Does NOT resolve DNS; the full SSRF
    guard in
    :meth:`freedom_search.enhancer.InternetSearchEnhancer._http_get`
    performs the DNS check.

    Rejects:
      * Empty or non-string values.
      * Schemes other than ``http``/``https`` (blocks ``file://``,
        ``gopher://``, ``ftp://``, ``data:``, ``javascript:``, etc.).
      * URLs with embedded credentials (``http://user:pass@host/``) which
        can confuse parsers and were historically a parser-smuggling
        vector.
      * URLs with no hostname.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.username or parsed.password:
        return False
    hostname = parsed.hostname
    if not hostname or " " in hostname:
        # ``urlparse`` is lenient: it accepts malformed hostnames like
        # ``"exa mple.com"`` (with a space) and returns them verbatim.
        # ``requests`` would reject these at connect time, but the
        # SSRF guard should catch them pre-flight — otherwise an
        # attacker can probe hostname-parsing bugs in our stack.
        return False
    return True


def safe_url_for_log(url: str) -> str:
    """Return a URL safe to include in logs: credentials stripped.

    Preserves scheme, host, port, path, and query string so log entries
    retain debugging context, but removes userinfo to prevent password
    leaks (e.g. ``http://user:hunter2@example.com/`` becomes
    ``http://example.com/``).

    This is log-hygiene only — :func:`is_safe_url` still rejects
    credentialed URLs at the validation boundary. We sanitize here so
    that any WARNING log that includes the URL never carries the
    password.
    """
    if not url or not isinstance(url, str):
        return ""
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        # Unparseable URLs are redacted to a placeholder rather than
        # logged verbatim, so the raw input cannot reach log files.
        return "<unparseable-url>"
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


def sanitize_text(text: str) -> str:
    """Strip control characters and collapse whitespace runs.

    Used to clean externally-sourced text before it is concatenated into
    an LLM prompt. Strips ASCII control chars (except tab, newline, and
    carriage return) and collapses any whitespace run into a single
    space. This blocks null bytes, ANSI escapes, and similar tricks
    from confusing downstream parsers or log analysis tools.
    """
    if not text:
        return ""
    text = _CONTROL_CHARS_RE.sub("", text)
    text = _WHITESPACE_RE.sub(" ", text)
    return text.strip()


def hash_query(query: str) -> str:
    """Return a short, stable hash of ``query`` for safe logging.

    Avoids putting the raw query (which may contain PII or secrets) into
    log files. The first 12 hex chars of SHA-256 give ~48 bits of
    collision resistance, plenty for log correlation.
    """
    if not query:
        return ""
    return hashlib.sha256(query.encode("utf-8", errors="replace")).hexdigest()[:12]
