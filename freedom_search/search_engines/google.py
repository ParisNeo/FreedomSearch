from freedom_search.search_engines.base import SearchEngine
from pipmaster import PackageManager
from ascii_colors import ASCIIColors

pm = PackageManager()
GOOGLE_SEARCH_AVAILABLE = False

# Check if the module can be imported
if not pm.is_installed("googlesearch-python"):
    # Install the package using its pip install name
    pm.install("googlesearch-python")

try:
    from googlesearch import search as google_search
    GOOGLE_SEARCH_AVAILABLE = True
except ImportError:
    ASCIIColors.red("Google search not available. To enable, install googlesearch-python library.")

class GoogleSearch(SearchEngine):
    def search(self, query, num_results=5):
        if not GOOGLE_SEARCH_AVAILABLE:
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