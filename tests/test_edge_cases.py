import unittest
from unittest.mock import patch, MagicMock

from freedom_search import InternetSearchEnhancer


class TestEnhancerIntegration(unittest.TestCase):
    """End-to-end tests for the InternetSearchEnhancer workflow."""

    def setUp(self):
        self.enhancer = InternetSearchEnhancer('duckduckgo')

    @patch('freedom_search.enhancer.requests.Session.get')
    @patch('freedom_search.enhancer.socket.getaddrinfo',
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_full_enhancement_flow(self, mock_getaddrinfo, mock_session_get):
        """Mocked search + mocked URL fetch must produce a valid enhanced prompt."""
        # Mock the search engine to return one fake result
        self.enhancer.current_engine = MagicMock()
        self.enhancer.current_engine.search.return_value = [
            {'title': 'Quantum Article', 'url': 'http://test.com/q', 'snippet': 'A snippet'}
        ]

        # Mock the URL fetch. extract_info now streams the body via
        # iter_content (with a 5 MiB cap) instead of buffering .text,
        # so the mock must provide iter_content and encoding.
        mock_response = MagicMock()
        mock_response.encoding = 'utf-8'
        mock_response.iter_content.return_value = [
            b'<html><body><p>Quantum computing uses qubits.</p></body></html>'
        ]
        mock_response.raise_for_status = MagicMock()
        mock_session_get.return_value = mock_response

        result = self.enhancer.enhance_llm_input(
            "Explain quantum computing", "recent quantum breakthroughs"
        )

        self.assertIn("Explain quantum computing", result)
        self.assertIn("Additional context", result)
        self.assertIn("quantum computing uses qubits", result)
        # Timeout must be passed to prevent indefinite hangs.
        # _http_get uses self._http.get which is the Session's get.
        first_call = mock_session_get.call_args_list[0]
        self.assertEqual(first_call.args[0], "http://test.com/q")
        self.assertEqual(first_call.kwargs.get("timeout"), 10)

    @patch('freedom_search.enhancer.requests.Session.get')
    def test_enhancement_handles_extraction_error(self, mock_session_get):
        """If URL extraction fails, the enhancement must still complete gracefully."""
        self.enhancer.current_engine = MagicMock()
        self.enhancer.current_engine.search.return_value = [
            {'title': 'Bad URL', 'url': 'http://broken.com', 'snippet': ''}
        ]
        mock_session_get.side_effect = Exception("DNS failure")

        result = self.enhancer.enhance_llm_input("Original", "query")

        self.assertIn("Original", result)
        self.assertIn("Additional context", result)
        # preprocess_text() lowercases the text, so the error string is
        # normalized to "error extracting info: ..." in the output.
        self.assertIn("error extracting info", result.lower())

    def test_cache_prevents_redundant_engine_calls(self):
        """Repeated identical searches must hit the TTL cache, not the engine."""
        self.enhancer.current_engine = MagicMock()
        self.enhancer.current_engine.search.return_value = [
            {'title': 'Cached', 'url': 'http://c.com', 'snippet': ''}
        ]

        # Clear any pre-existing cache state for a clean test
        self.enhancer.cache_clear()

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

        # v0.4: cache_clear moved from the search() function (under the
        # old @lru_cache decorator) to the enhancer instance.
        self.enhancer.cache_clear()

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
