"""Google search engine.

Uses the ``googlesearch-python`` package, which only exposes the URL of each
hit (no title or snippet metadata). When the package is unavailable, the
engine degrades to a no-op that returns an empty list, so the rest of the
library continues to function with the remaining engines.
"""
from freedom_search.search_engines.base import SearchEngine
from freedom_search.utils import is_safe_url
import logging

logger = logging.getLogger(__name__)

# Module-level availability flag + swappable function reference.
# The test suite relies on these names, so they must remain stable.
#
# Security note: we intentionally do NOT auto-install googlesearch-python
# at import time. Runtime pip-installs (a) bypass requirements.txt pinning,
# (b) re-introduce the well-known supply-chain risk against this package,
# and (c) mask malicious payloads behind a broad except. Dependencies must
# be declared and audited in requirements.txt.
GOOGLE_SEARCH_AVAILABLE = False
google_search = None

try:
    from googlesearch import search as google_search  # noqa: F811
    GOOGLE_SEARCH_AVAILABLE = True
    logger.debug("googlesearch-python loaded successfully")
except ImportError as exc:
    GOOGLE_SEARCH_AVAILABLE = False
    google_search = None
    logger.info(
        "Google search backend unavailable (%s). "
        "Install 'googlesearch-python' to enable it. "
        "Falling back to other engines.",
        exc,
    )


class GoogleSearch(SearchEngine):
    """Google search via ``googlesearch-python``.

    Note:
        The underlying library only returns URLs. ``title`` falls back to
        the URL and ``snippet`` is always empty.
    """

    def search(self, query, num_results=5):
        """Perform a Google search and return the results as a list of dicts.

        Args:
            query (str): The search query string to send to Google.
            num_results (int, optional): Maximum number of results to retrieve.
                Defaults to 5.

        Returns:
            list[dict]: A list of result dictionaries with ``title``, ``url``,
            and ``snippet`` keys. When the underlying library is unavailable,
            returns an empty list rather than raising.
        """
        if not GOOGLE_SEARCH_AVAILABLE or google_search is None:
            logger.debug(
                "Skipping Google search for query=%r: backend unavailable.",
                query,
            )
            return []

        try:
            raw_results = list(google_search(query, num_results=num_results))
        except Exception as exc:  # noqa: BLE001
            # googlesearch-python is fragile (rate limits, captchas, blocks).
            # Treat any failure as a soft error so other engines can take over.
            logger.warning("Google search failed for query=%r: %s", query, exc)
            return []

        results = []
        for url in raw_results:
            # Defense in depth: drop any URL that fails the safety
            # pre-check. The enhancer's SSRF guard would also reject
            # these, but filtering here keeps the LLM context clean and
            # avoids wasted fetches when the engine is used standalone
            # (e.g. directly by a unit test, agent, or alternate caller).
            if not isinstance(url, str) or not is_safe_url(url):
                continue
            results.append({
                'title': url,
                'url': url,
                'snippet': '',  # Library limitation: no snippets exposed.
            })
        return results
