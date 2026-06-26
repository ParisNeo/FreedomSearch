"""DuckDuckGo HTML search engine.

Uses the public ``html.duckduckgo.com/html/`` endpoint, which does not
require an API key. Returns a list of result dicts with ``title``,
``url``, and ``snippet`` keys.

The URLs returned by DuckDuckGo are filtered through
:func:`freedom_search.utils.is_safe_url` as a defense-in-depth measure;
the enhancer's SSRF guard will also reject any unsafe URL before it is
fetched.
"""
import logging

import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus

from freedom_search.search_engines.base import SearchEngine
from freedom_search.utils import is_safe_url

logger = logging.getLogger(__name__)


# Conservative, generic User-Agent. Kept as a real-browser UA so DDG
# serves the HTML results page (a bare curl UA gets a JS challenge),
# but rotated away from an outdated, easily-fingerprinted version.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Content-Types we are willing to parse as HTML. Anything else means
# the response is a captcha challenge, error page, or something else
# BS4 will not handle cleanly.
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml")

# Hard cap regardless of what the caller asks for. Prevents a malicious
# caller from asking for 10000 results and forcing us to parse a huge
# page.
_MAX_RESULTS_HARD_CAP = 50


class DuckDuckGoSearch(SearchEngine):
    def __init__(self):
        self.search_url = "https://html.duckduckgo.com/html/"

    def search(self, query, num_results=5):
        # Defensive input validation. The enhancer validates its own
        # inputs, but the engine is a public API.
        if not isinstance(query, str) or not query.strip():
            logger.warning("DuckDuckGoSearch: empty/invalid query")
            return []
        if not isinstance(num_results, int) or num_results < 1:
            num_results = 5
        num_results = min(num_results, _MAX_RESULTS_HARD_CAP)

        encoded_query = quote_plus(query)
        headers = {"User-Agent": _USER_AGENT}
        try:
            response = requests.get(
                f"{self.search_url}?q={encoded_query}",
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            # A single network blip must not crash the caller. Degrade
            # to an empty result so other engines can take over.
            logger.warning("DuckDuckGo request failed: %s", exc)
            return []

        # Content-Type gate. DDG should always return HTML, but if it
        # ever returns a captcha or error page, we don't want to feed
        # it to BS4. We reject only when we can positively identify a
        # non-HTML Content-Type; missing/empty/unparseable headers are
        # accepted so BS4 gets a chance to parse whatever came back.
        ctype = response.headers.get("Content-Type", "")
        if isinstance(ctype, str) and ctype:
            ctype_lower = ctype.lower()
            if not any(t in ctype_lower for t in _HTML_CONTENT_TYPES):
                logger.warning(
                    "DuckDuckGo returned unexpected Content-Type %r",
                    ctype,
                )
                return []

        soup = BeautifulSoup(response.text, "html.parser")

        results = []
        for result in soup.find_all("div", class_="result")[:num_results]:
            title_elem = result.find("h2", class_="result__title")
            snippet_elem = result.find("a", class_="result__snippet")

            if not title_elem or not snippet_elem:
                continue
            link_elem = title_elem.find("a")
            if not link_elem or not link_elem.get("href"):
                continue

            url = link_elem["href"]
            # Defense in depth: drop any URL that fails the safety
            # pre-check. The enhancer's SSRF guard would also reject
            # these, but filtering here keeps the LLM context clean and
            # avoids wasted fetches.
            if not is_safe_url(url):
                continue

            results.append({
                "title": title_elem.text.strip(),
                "url": url,
                "snippet": snippet_elem.text.strip(),
            })

        return results
