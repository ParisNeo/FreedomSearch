from freedom_search.search_engines.base import SearchEngine

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------
# `pipmaster` is used to auto-install `googlesearch-python` on first use, and
# `ascii_colors` is used to print a colored warning if the import fails.
#
# Both are treated as OPTIONAL: if either is missing (or fails to construct,
# e.g. in a read-only / PEP 668 / sandboxed environment), the rest of the
# freedom_search library MUST remain importable. Without this guard, a missing
# optional dep would cascade an ImportError all the way up to:
#     from freedom_search import InternetSearchEnhancer
# ...even for users who only ever use DuckDuckGoSearch.
# ---------------------------------------------------------------------------
try:
    from pipmaster import PackageManager
    from ascii_colors import ASCIIColors
    _pm = PackageManager()
except ImportError:
    PackageManager = None
    ASCIIColors = None
    _pm = None

GOOGLE_SEARCH_AVAILABLE = False
google_search = None

# ---------------------------------------------------------------------------
# Best-effort: ensure `googlesearch-python` is installed, then import it.
# Any failure here is swallowed: the worst case is that
# GOOGLE_SEARCH_AVAILABLE stays False and GoogleSearch.search() returns [].
# ---------------------------------------------------------------------------
if _pm is not None:
    try:
        if not _pm.is_installed("googlesearch-python"):
            _pm.install("googlesearch-python")
    except Exception:
        # Sandboxed envs, read-only filesystems, PEP 668, network failures...
        # We silently degrade rather than blowing up the import chain.
        pass

try:
    from googlesearch import search as _google_search
    google_search = _google_search
    GOOGLE_SEARCH_AVAILABLE = True
except ImportError:
    if ASCIIColors is not None:
        ASCIIColors.red(
            "Google search not available. "
            "To enable, install googlesearch-python library."
        )


class GoogleSearch(SearchEngine):
    def search(self, query, num_results=5):
        if not GOOGLE_SEARCH_AVAILABLE or google_search is None:
            # Library not importable; fail closed with an empty result set
            # rather than raising NameError on the unbound `google_search` name.
            return []
        results = []
        for j in google_search(query, num_results=num_results):
            results.append({
                'title': j,
                'url': j,
                'snippet': ''  # Google search library doesn't provide snippets
            })
        return results
