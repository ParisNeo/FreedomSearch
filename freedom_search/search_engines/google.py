from freedom_search.search_engines.base import SearchEngine
from pipmaster import PackageManager
from ascii_colors import ASCIIColors
pm = PackageManager()
# Check if the module can be imported
if not pm.is_installed("googlesearch-python"):
    # Install the package using its pip install name
    pm.install("googlesearch-python")

try:
    from googlesearch import search as google_search
except ImportError:
    ASCIIColors.red("Google search not available. To enable, install googlesearch-python library.")

class GoogleSearch(SearchEngine):
    def search(self, query, num_results=5):
        results = []
        for j in google_search(query, num_results=num_results):
            results.append({
                'title': j,
                'url': j,
                'snippet': ''  # Google search library doesn't provide snippets
            })
        return results