"""
Comprehensive unit tests for search engine implementations and registration.

These tests complement test_integration.py by focusing on:
    * URL construction and percent-encoding details
    * Timeout enforcement on outbound HTTP calls
    * Search engine registration / lookup in InternetSearchEnhancer
    * The abstract SearchEngine contract
    * Google-specific fallback behavior under the GOOGLE_SEARCH_AVAILABLE flag
"""
import unittest
from unittest.mock import patch, MagicMock
from urllib.parse import quote_plus

from freedom_search import InternetSearchEnhancer
from freedom_search.search_engines.base import SearchEngine
from freedom_search.search_engines.duckduckgo import DuckDuckGoSearch
import freedom_search.search_engines.google as google_module
from freedom_search.search_engines.google import GoogleSearch


class TestDuckDuckGoURLConstruction(unittest.TestCase):
    """Verify the DuckDuckGo engine builds well-formed request URLs."""

    def setUp(self):
        self.engine = DuckDuckGoSearch()

    def test_search_url_uses_https(self):
        """The endpoint must be HTTPS to protect query privacy in transit."""
        self.assertTrue(self.engine.search_url.startswith("https://"))

    def test_search_url_points_to_html_endpoint(self):
        """Must target the html.duckduckgo.com HTML endpoint."""
        self.assertIn("duckduckgo.com", self.engine.search_url)
        self.assertIn("/html/", self.engine.search_url)

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_query_is_percent_encoded(self, mock_get):
        """Spaces and reserved characters must be percent-encoded."""
        mock_response = MagicMock()
        mock_response.text = "<html><body></body></html>"
        mock_get.return_value = mock_response

        raw_query = "test query with spaces & symbols!"
        self.engine.search(raw_query)

        called_url = mock_get.call_args.args[0]
        self.assertIn(quote_plus(raw_query), called_url)
        # The raw space must not appear in the encoded query string.
        query_part = called_url.split("?q=", 1)[1]
        self.assertNotIn(" ", query_part)

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_timeout_is_set(self, mock_get):
        """A timeout must be supplied to prevent indefinite hangs."""
        mock_response = MagicMock()
        mock_response.text = "<html><body></body></html>"
        mock_get.return_value = mock_response

        self.engine.search("test")
        call_kwargs = mock_get.call_args.kwargs
        self.assertIn('timeout', call_kwargs)
        self.assertIsNotNone(call_kwargs['timeout'])
        self.assertGreater(call_kwargs['timeout'], 0)


class TestDuckDuckGoResultParsing(unittest.TestCase):
    """Verify result parsing edge cases."""

    def setUp(self):
        self.engine = DuckDuckGoSearch()

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_html_entities_are_decoded(self, mock_get):
        """Entities like &amp; and &quot; must be decoded by BeautifulSoup."""
        mock_response = MagicMock()
        mock_response.text = """
        <html><body>
            <div class="result">
                <h2 class="result__title">
                    <a href="http://example.com/1">Tom &amp; Jerry &lt;3</a>
                </h2>
                <a class="result__snippet">A &quot;classic&quot; show</a>
            </div>
        </body></html>
        """
        mock_get.return_value = mock_response

        results = self.engine.search("cartoon")
        self.assertEqual(len(results), 1)
        self.assertIn("Tom & Jerry", results[0]['title'])
        self.assertIn('"', results[0]['snippet'])

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_single_result(self, mock_get):
        """A page with one result must return a list of length 1."""
        mock_response = MagicMock()
        mock_response.text = """
        <html><body>
            <div class="result">
                <h2 class="result__title">
                    <a href="http://example.com/single">Only Result</a>
                </h2>
                <a class="result__snippet">Only snippet</a>
            </div>
        </body></html>
        """
        mock_get.return_value = mock_response

        results = self.engine.search("query")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['title'], 'Only Result')
        self.assertEqual(results[0]['url'], 'http://example.com/single')
        self.assertEqual(results[0]['snippet'], 'Only snippet')

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_preserves_document_order(self, mock_get):
        """Results must be returned in document order."""
        mock_response = MagicMock()
        items = "".join([
            f"""
            <div class="result">
                <h2 class="result__title"><a href="http://e.com/{i}">Title {i}</a></h2>
                <a class="result__snippet">Snippet {i}</a>
            </div>
            """ for i in range(5)
        ])
        mock_response.text = f"<html><body>{items}</body></html>"
        mock_get.return_value = mock_response

        results = self.engine.search("query", num_results=5)
        self.assertEqual(
            [r['title'] for r in results],
            ['Title 0', 'Title 1', 'Title 2', 'Title 3', 'Title 4'],
        )

    @patch('freedom_search.search_engines.duckduckgo.requests.get')
    def test_result_dict_has_required_keys(self, mock_get):
        """Every result must contain title, url, and snippet keys."""
        mock_response = MagicMock()
        mock_response.text = """
        <html><body>
            <div class="result">
                <h2 class="result__title">
                    <a href="http://example.com/x">X</a>
                </h2>
                <a class="result__snippet">Y</a>
            </div>
        </body></html>
        """
        mock_get.return_value = mock_response

        results = self.engine.search("query")
        self.assertEqual(len(results), 1)
        for key in ('title', 'url', 'snippet'):
            self.assertIn(key, results[0])


class TestGoogleSearchBehavior(unittest.TestCase):
    """Additional Google search behavior tests."""

    def setUp(self):
        self.engine = GoogleSearch()

    def test_search_returns_empty_when_unavailable(self):
        """When GOOGLE_SEARCH_AVAILABLE is False, search() must return []."""
        original = google_module.GOOGLE_SEARCH_AVAILABLE
        google_module.GOOGLE_SEARCH_AVAILABLE = False
        try:
            self.assertEqual(self.engine.search("query"), [])
        finally:
            google_module.GOOGLE_SEARCH_AVAILABLE = original

    def test_search_passes_num_results(self):
        """num_results must be forwarded to the google_search function."""
        original_available = google_module.GOOGLE_SEARCH_AVAILABLE
        original_search = getattr(google_module, 'google_search', None)

        google_module.GOOGLE_SEARCH_AVAILABLE = True
        received_num = []

        def mock_google_search(query, num_results=5):
            received_num.append(num_results)
            return iter([])

        google_module.google_search = mock_google_search
        try:
            self.engine.search("query", num_results=7)
            self.assertEqual(received_num, [7])
        finally:
            google_module.GOOGLE_SEARCH_AVAILABLE = original_available
            if original_search is not None:
                google_module.google_search = original_search

    def test_search_result_structure(self):
        """Google results must have title, url, snippet keys; snippet is empty."""
        original_available = google_module.GOOGLE_SEARCH_AVAILABLE
        original_search = getattr(google_module, 'google_search', None)

        google_module.GOOGLE_SEARCH_AVAILABLE = True

        def mock_google_search(query, num_results=5):
            return iter(['http://a.com', 'http://b.com'])

        google_module.google_search = mock_google_search
        try:
            results = self.engine.search("query")
            self.assertEqual(len(results), 2)
            for r in results:
                self.assertIn('title', r)
                self.assertIn('url', r)
                self.assertIn('snippet', r)
                self.assertEqual(r['title'], r['url'])  # Library limitation
                self.assertEqual(r['snippet'], '')
        finally:
            google_module.GOOGLE_SEARCH_AVAILABLE = original_available
            if original_search is not None:
                google_module.google_search = original_search


class TestSearchEngineRegistry(unittest.TestCase):
    """Verify how search engines are registered and looked up in the enhancer."""

    def test_default_engines_registered(self):
        """Both duckduckgo and google must be registered by default."""
        enhancer = InternetSearchEnhancer()
        self.assertIn('duckduckgo', enhancer.search_engines)
        self.assertIn('google', enhancer.search_engines)

    def test_registered_engines_are_searchengine_instances(self):
        """All registered engines must be SearchEngine subclasses."""
        enhancer = InternetSearchEnhancer()
        for name, engine in enhancer.search_engines.items():
            self.assertIsInstance(
                engine, SearchEngine,
                f"{name} is not a SearchEngine instance",
            )

    def test_default_engine_is_duckduckgo(self):
        """The default engine must be duckduckgo (privacy-first)."""
        enhancer = InternetSearchEnhancer()
        self.assertIs(enhancer.current_engine, enhancer.search_engines['duckduckgo'])

    def test_can_specify_engine_at_init(self):
        """Passing an engine name to __init__ must set it as current."""
        enhancer = InternetSearchEnhancer('google')
        self.assertIs(enhancer.current_engine, enhancer.search_engines['google'])

    def test_engines_are_independent_instances(self):
        """Each enhancer must own its engine instances (no shared globals)."""
        e1 = InternetSearchEnhancer()
        e2 = InternetSearchEnhancer()
        self.assertIsNot(
            e1.search_engines['duckduckgo'],
            e2.search_engines['duckduckgo'],
        )
        self.assertIsNot(
            e1.search_engines['google'],
            e2.search_engines['google'],
        )


class TestSearchEngineAbstractContract(unittest.TestCase):
    """Verify the abstract base class contract."""

    def test_subclass_without_search_cannot_instantiate(self):
        """A subclass that omits search() must fail to instantiate."""
        class IncompleteEngine(SearchEngine):
            pass

        with self.assertRaises(TypeError):
            IncompleteEngine()

    def test_subclass_with_search_can_instantiate(self):
        """A subclass implementing search() must instantiate cleanly."""
        class CompleteEngine(SearchEngine):
            def search(self, query, num_results=5):
                return []

        engine = CompleteEngine()
        self.assertEqual(engine.search("anything"), [])

    def test_engine_returns_list_of_dicts_contract(self):
        """The contract is that search() returns a list of dicts."""
        class CustomEngine(SearchEngine):
            def search(self, query, num_results=5):
                return [{'title': query, 'url': f'http://{query}', 'snippet': ''}]

        engine = CustomEngine()
        results = engine.search("x")
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], dict)


if __name__ == '__main__':
    unittest.main()