import unittest
from unittest.mock import patch, MagicMock

from freedom_search import InternetSearchEnhancer


class TestEnhancerIntegration(unittest.TestCase):
    """End-to-end tests for the InternetSearchEnhancer workflow."""

    def setUp(self):
        self.enhancer = InternetSearchEnhancer('duckduckgo')

    @patch('freedom_search.enhancer.requests.get')
    def test_full_enhancement_flow(self, mock_get):
        """Mocked search + mocked URL fetch must produce a valid enhanced prompt."""
        # Mock the search engine to return one fake result
        self.enhancer.current_engine = MagicMock()
        self.enhancer.current_engine.search.return_value = [
            {'title': 'Quantum Article', 'url': 'http://test.com/q', 'snippet': 'A snippet'}
        ]

        # Mock the URL fetch
        mock_response = MagicMock()
        mock_response.text = '<html><body><p>Quantum computing uses qubits.</p></body></html>'
        mock_get.return_value = mock_response

        result = self.enhancer.enhance_llm_input(
            "Explain quantum computing", "recent quantum breakthroughs"
        )

        self.assertIn("Explain quantum computing", result)
        self.assertIn("Additional context", result)
        self.assertIn("quantum computing uses qubits", result)
        # Timeout must be passed to prevent indefinite hangs
        mock_get.assert_called_once_with("http://test.com/q", timeout=10)

    @patch('freedom_search.enhancer.requests.get')
    def test_enhancement_handles_extraction_error(self, mock_get):
        """If URL extraction fails, the enhancement must still complete gracefully."""
        self.enhancer.current_engine = MagicMock()
        self.enhancer.current_engine.search.return_value = [
            {'title': 'Bad URL', 'url': 'http://broken.com', 'snippet': ''}
        ]
        mock_get.side_effect = Exception("DNS failure")

        result = self.enhancer.enhance_llm_input("Original", "query")

        self.assertIn("Original", result)
        self.assertIn("Additional context", result)
        # preprocess_text() lowercases the text, so the error string is
        # normalized to "error extracting info: dns failure" in the output.
        self.assertIn("error extracting info", result.lower())

    def test_cache_prevents_redundant_engine_calls(self):
        """Repeated identical searches must hit the lru_cache, not the engine."""
        self.enhancer.current_engine = MagicMock()
        self.enhancer.current_engine.search.return_value = [
            {'title': 'Cached', 'url': 'http://c.com', 'snippet': ''}
        ]

        # Clear any pre-existing cache state for a clean test
        self.enhancer.search.cache_clear()

        self.enhancer.search("unique-cache-key-123")
        self.enhancer.search("unique-cache-key-123")
        self.enhancer.search("unique-cache-key-123")

        self.enhancer.current_engine.search.assert_called_once()

    def test_cache_distinguishes_num_results(self):
        """Different num_results must produce different cache entries."""
        self.enhancer.current_engine = MagicMock()
        self.enhancer.current_engine.search.return_value = [
            {'title': 'X', 'url': 'http://x.com', 'snippet': ''}
        ]

        self.enhancer.search.cache_clear()

        self.enhancer.search("query-cache-key-456", num_results=5)
        self.enhancer.search("query-cache-key-456", num_results=10)

        self.assertEqual(self.enhancer.current_engine.search.call_count, 2)
        calls = self.enhancer.current_engine.search.call_args_list
        self.assertEqual(calls[0].args[1], 5)
        self.assertEqual(calls[1].args[1], 10)

    def test_set_search_engine_round_trip(self):
        """set_search_engine must swap the current engine reference correctly."""
        original_duck = self.enhancer.search_engines['duckduckgo']
        original_google = self.enhancer.search_engines['google']

        self.enhancer.set_search_engine('google')
        self.assertIs(self.enhancer.current_engine, original_google)

        self.enhancer.set_search_engine('duckduckgo')
        self.assertIs(self.enhancer.current_engine, original_duck)


if __name__ == '__main__':
    unittest.main()
