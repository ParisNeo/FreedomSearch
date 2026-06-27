# Changelog

All notable changes to FreedomSearch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2026-06-26 14:42]

- feat: bump version to 0.5.0 and export safe_url_for_log

## [0.5.0] - 2026-06-26

### Added
- **`freedom_search.utils.safe_url_for_log`**: New public utility that
  returns a URL safe to include in log messages by stripping embedded
  credentials (e.g. `http://user:hunter2@example.com/` becomes
  `http://example.com/`). Preserves scheme, host, port, path, and query
  string so log entries retain debugging context without leaking
  passwords. Exported from the top-level package as
  `from freedom_search import safe_url_for_log`.
- **`SearchConfig.strict_peer_ip`**: New opt-in flag (default `False`)
  that makes the DNS-rebinding defense fail closed when the peer IP of
  the established connection cannot be verified (e.g. behind unusual
  transports or proxies). The default preserves backward-compatible
  best-effort behavior with WARNING-level logging.
- **`SearchConfig.max_redirects`**: New config field (default `5`) that
  caps the number of manually-followed redirect hops. Each hop is
  re-validated against the SSRF guard, defeating the public-to-internal
  redirect bypass.
- **`InternetSearchEnhancer.enhance_llm_input`**: Per-call randomized
  delimiters (`<<<EXTERNAL_CONTEXT_<64-bit-suffix>>>` and matching
  end-marker). The 64-bit suffix is generated via `secrets.token_hex(8)`
  so an attacker page cannot inject a matching end-marker to escape the
  trust boundary.
- **`CHANGELOG.md`**: This file. Future releases will document changes
  here in Keep-a-Changelog format.

### Changed
- **`InternetSearchEnhancer._http_get`**: Log messages now use the
  sanitized URL produced by `safe_url_for_log`, and exception messages
  are scrubbed of any embedded raw URL. URL credentials can no longer
  reach log files even when the underlying `requests` exception
  embeds the full URL.
- **`InternetSearchEnhancer._validate_response_peer_ip`**: Refactored
  to a flag-based control flow. The previous nested-closure design
  silently caught the guard's own `RequestException` raise (because
  `requests.RequestException` inherits from `OSError`), creating an
  SSRF-defense regression. Both raises (unverifiable peer in strict
  mode, internal peer IP in any mode) now execute outside any
  `try/except` block.
- **`InternetSearchEnhancer._validate_url_for_ssrf`**: Previously
  silent failures (e.g. DNS error in `_http_get_safe`) now surface as
  `requests.RequestException` with a clear "Cannot resolve hostname"
  message rather than bubbling up as a generic `gaierror`.
- **`GoogleSearch`**: Now filters results through `is_safe_url` at the
  engine boundary, matching the defense-in-depth behavior already
  present in `DuckDuckGoSearch`. URLs that fail the pre-check never
  enter the LLM context even if the engine is used standalone (e.g.
  directly by a test, agent, or alternate caller).

### Security
- **SSRF: IPv4-mapped IPv6 bypass closed (CWE-918)**.
  `freedom_search.utils.is_internal_ip` previously treated `::ffff:
  127.0.0.1` (and other IPv4-mapped IPv6 addresses) as public because
  Python's `IPv6Address.is_loopback` / `.is_private` / etc. do not
  inspect the embedded IPv4 suffix. The function now recurses through
  `ip.ipv4_mapped` to re-validate the v4 form, closing the bypass for
  addresses like `::ffff:127.0.0.1`, `::ffff:10.0.0.1`, and
  `::ffff:169.254.169.254` (AWS IMDS).
- **SSRF: DNS-rebinding defense hardening (CWE-918)**.
  `_validate_response_peer_ip` previously swallowed its own SSRF-guard
  raise inside a nested `try/except (..., OSError, ...)` block because
  `requests.RequestException ⊂ OSError`. With the flag-based refactor,
  connected peer addresses that resolve to loopback / private / link-
  local / etc. always raise, regardless of `strict_peer_ip`. Unverifiable
  transports log at WARNING (default) or raise in strict mode.
- **SSRF: Malformed-hostname pre-check (CWE-918)**.
  `is_safe_url` now rejects hostnames containing whitespace (e.g.
  `"exa mple.com"`), which `urllib.parse.urlparse` accepts verbatim.
  These inputs cannot be safely fetched and previously passed the
  pre-check before being rejected downstream by `requests`.
- **Prompt injection: Random per-call delimiter suffix (CWE-1427,
  OWASP LLM01)**. `enhance_llm_input` previously used fixed markers
  (`<<<EXTERNAL_CONTEXT>>>` and `<<<END_EXTERNAL_CONTEXT>>>`). An
  attacker page containing a literal end-marker could attempt to break
  the trust boundary. Each call now generates a 64-bit random suffix
  via `secrets.token_hex(8)`; the literal pre-v0.5 markers are no
  longer emitted, and any attacker-injected marker text is further
  neutralized by `preprocess_text` (lowercase + non-alpha strip), so
  `<<<END_EXTERNAL_CONTEXT>>>` becomes `endexternalcontext` before
  reaching the LLM context.
- **Log injection: URL credentials no longer leaked (CWE-532)**.
  `_http_get` previously logged the raw URL on fetch failure, which
  embedded credentials in userinfo (`http://user:hunter2@host/`) into
  log files. The new `safe_url_for_log` helper plus
  `_scrub_url_in_msg` exception-message scrubber ensure that
  WARNING-level logs never carry passwords.
- **Test coverage: 80 new security tests**.
  `tests/test_security.py` covers the SSRF chain (22 tests), prompt-
  injection defense (5 tests), DoS caps (8 tests), cache isolation (3
  tests), logging hygiene (3 tests), and config defaults (3 tests).
  Plus 15 engine-level safety-filter tests in
  `tests/test_search_engines_security.py`. Total suite: 128 tests.

## [0.4.0] - Earlier

Pre-history. FreedomSearch v0.4 introduced:
- DRY refactor delegating helper functions to `freedom_search.utils`.
- `tenacity`-based retry on transient network errors.
- Instance-level `TTLCache` replacing `functools.lru_cache` (1 h TTL,
  bounded size).
- `trafilatura` extraction on substantial HTML with BS4 cascade as
  fallback.
- Multi-engine fan-out via `search_all` with vote-based score boost.
- Relevance scoring in [0, 1] for every result.

[0.5.0]: https://github.com/ParisNeo/FreedomSearch/releases/tag/v0.5.0
