import unittest
from unittest.mock import patch, MagicMock

from freedom_search.search_engines.base import SearchEngine
from freedom_search.search_engines.duckduckgo import DuckDuckGoSearch
import freedom_search.search_engines.google as google_module
from freedom_search.search_engines.google import GoogleSearch


class TestSearchEngineBase(unittest.TestCase):
    """Tests for the abstract SearchEngine base class."""

    def test_cannot_instantiate_abstract_class(self):
        """SearchEngine is abstract; direct instantiation must raise TypeError."""
        with self.assertRaises(TypeError):
            SearchEngine()


class TestDuckDuckGoSearch(unittest.TestCase):
    """Tests for the DuckDuckGo search engine."""

    def setUp(self):
        self.engine = DuckDuckGoSearch()

    def test_search_url_is_set(self):
        """The search engine must point to the DuckDuckGo HTML endpoint."""
        self.assertTrue(self.engine.search_url.startswith("https://"))

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_search_parses_results(self, mock_get):
        """A well-formed HTML response must yield a list of dicts."""
        mock_response = MagicMock()
        mock_response.text = """
        <html><body>
            <div class="result">
                <h2 class="result__title">
                    <a href="http://example.com/article1">Example Title 1</a>
                </h2>
                <a class="result__snippet">This is the first snippet</a>
            </div>
            <div class="result">
                <h2 class="result__title">
                    <a href="http://example.com/article2">Example Title 2</a>
                </h2>
                <a class="result__snippet">This is the second snippet</a>
            </div>
        </body></html>
        """
        mock_get.return_value = mock_response

        results = self.engine.search("test query", num_results=5)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['title'], 'Example Title 1')
        self.assertEqual(results[0]['url'], 'http://example.com/article1')
        self.assertEqual(results[0]['snippet'], 'This is the first snippet')
        self.assertEqual(results[1]['title'], 'Example Title 2')

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_search_no_results(self, mock_get):
        """An empty HTML page must yield an empty results list."""
        mock_response = MagicMock()
        mock_response.text = "<html><body></body></html>"
        mock_get.return_value = mock_response

        results = self.engine.search("obscure query with no hits")
        self.assertEqual(results, [])

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_search_respects_num_results(self, mock_get):
        """num_results must cap the number of returned items."""
        mock_response = MagicMock()
        items = "".join([
            f"""
            <div class="result">
                <h2 class="result__title"><a href="http://e.com/{i}">T{i}</a></h2>
                <a class="result__snippet">S{i}</a>
            </div>
            """ for i in range(10)
        ])
        mock_response.text = f"<html><body>{items}</body></html>"
        mock_get.return_value = mock_response

        results = self.engine.search("query", num_results=3)
        self.assertEqual(len(results), 3)

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_search_sends_user_agent(self, mock_get):
        """A User-Agent header must be set to avoid blocks."""
        mock_response = MagicMock()
        mock_response.text = "<html><body></body></html>"
        mock_get.return_value = mock_response

        self.engine.search("query")
        # Inspect the kwargs/headers passed to requests.get
        call_kwargs = mock_get.call_args.kwargs
        self.assertIn('headers', call_kwargs)
        self.assertIn('User-Agent', call_kwargs['headers'])

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_search_skips_malformed_results(self, mock_get):
        """Results missing title or snippet elements must be skipped gracefully."""
        mock_response = MagicMock()
        mock_response.text = """
        <html><body>
            <div class="result">
                <!-- Missing h2 and snippet -->
            </div>
            <div class="result">
                <h2 class="result__title">
                    <a href="http://example.com/good">Good Result</a>
                </h2>
                <a class="result__snippet">Good snippet</a>
            </div>
        </body></html>
        """
        mock_get.return_value = mock_response

        results = self.engine.search("query")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['title'], 'Good Result')

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_search_propagates_network_errors(self, mock_get):
        """Network errors must propagate (caller is expected to handle)."""
        mock_get.side_effect = Exception("Connection refused")
        with self.assertRaises(Exception):
            self.engine.search("query")


class TestGoogleSearch(unittest.TestCase):
    """Tests for the Google search engine, including fallback behavior."""

    def setUp(self):
        self.engine = GoogleSearch()

    def test_search_returns_empty_when_library_unavailable(self):
        """If googlesearch-python failed to import, search() must return [] not raise."""
        original = google_module.GOOGLE_SEARCH_AVAILABLE
        google_module.GOOGLE_SEARCH_AVAILABLE = False
        try:
            results = self.engine.search("test query")
            self.assertEqual(results, [])
        finally:
            google_module.GOOGLE_SEARCH_AVAILABLE = original

    def test_search_uses_google_search_function(self):
        """When available, search() must delegate to the googlesearch function."""
        original_available = google_module.GOOGLE_SEARCH_AVAILABLE
        original_search = getattr(google_module, 'google_search', None)

        google_module.GOOGLE_SEARCH_AVAILABLE = True

        def mock_google_search(query, num_results=5):
            return ['http://example1.com', 'http://example2.com', 'http://example3.com']

        google_module.google_search = mock_google_search
        try:
            results = self.engine.search("test query", num_results=3)
            self.assertEqual(len(results), 3)
            self.assertEqual(results[0]['url'], 'http://example1.com')
            self.assertEqual(results[1]['url'], 'http://example2.com')
            self.assertEqual(results[2]['url'], 'http://example3.com')
            # Title and URL are the same, snippet is empty (library limitation)
            self.assertEqual(results[0]['title'], 'http://example1.com')
            self.assertEqual(results[0]['snippet'], '')
        finally:
            google_module.GOOGLE_SEARCH_AVAILABLE = original_available
            if original_search is not None:
                google_module.google_search = original_search


if __name__ == '__main__':
    unittest.main()
