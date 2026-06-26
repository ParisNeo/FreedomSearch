import unittest
from unittest.mock import patch, MagicMock
from freedom_search import InternetSearchEnhancer

class TestInternetSearchEnhancer(unittest.TestCase):

    def setUp(self):
        self.enhancer = InternetSearchEnhancer()

    def test_init_default_engine(self):
        self.assertIsInstance(self.enhancer.current_engine, self.enhancer.search_engines['duckduckgo'].__class__)

    def test_set_search_engine_valid(self):
        self.enhancer.set_search_engine('google')
        self.assertIsInstance(self.enhancer.current_engine, self.enhancer.search_engines['google'].__class__)

    def test_set_search_engine_invalid(self):
        with self.assertRaises(ValueError):
            self.enhancer.set_search_engine('invalid_engine')

    @patch('freedom_search.enhancer.time.sleep')
    @patch('freedom_search.enhancer.time.time')
    def test_rate_limit(self, mock_time, mock_sleep):
        # Simulate "now is 0.5s after the last request"; min interval is 1.0s,
        # so the limiter must sleep for 0.5s. last_request_time starts at 0
        # from __init__, and both time.time() calls return 0.5.
        mock_time.return_value = 0.5
        self.enhancer._rate_limit()
        mock_sleep.assert_called_once_with(0.5)

    @patch.object(InternetSearchEnhancer, 'search')
    def test_enhance_llm_input_with_results(self, mock_search):
        mock_search.return_value = [
            {'title': 'Test', 'url': 'http://test.com', 'snippet': 'This is a test'}
        ]
        original_prompt = "Original prompt"
        search_query = "test query"
        result = self.enhancer.enhance_llm_input(original_prompt, search_query)
        self.assertTrue(original_prompt in result)
        self.assertTrue("Additional context" in result)

    @patch.object(InternetSearchEnhancer, 'search')
    def test_enhance_llm_input_no_results(self, mock_search):
        mock_search.return_value = []
        original_prompt = "Original prompt"
        search_query = "test query"
        result = self.enhancer.enhance_llm_input(original_prompt, search_query)
        self.assertTrue(original_prompt in result)
        self.assertTrue("No additional information found" in result)

    @patch.object(InternetSearchEnhancer, '_rate_limit')
    def test_search(self, mock_rate_limit):
        self.enhancer.current_engine = MagicMock()
        self.enhancer.current_engine.search.return_value = [
            {'title': 'Test', 'url': 'http://test.com', 'snippet': 'This is a test'}
        ]
        result = self.enhancer.search("test query")
        mock_rate_limit.assert_called_once()
        self.enhancer.current_engine.search.assert_called_once_with("test query", 5)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['title'], 'Test')

    def test_extract_info(self):
        # Patch the Session's get method (where extract_info actually
        # routes the HTTP call) rather than the module-level requests.get.
        # Also mock socket.getaddrinfo so the SSRF guard sees a public IP
        # (93.184.216.34 = example.com) without doing real DNS, and
        # provide iter_content + encoding because extract_info now streams
        # the body with a 5 MiB cap instead of buffering .text.
        with patch.object(self.enhancer._http, 'get') as mock_get, \
             patch('freedom_search.enhancer.socket.getaddrinfo',
                   return_value=[(2, 1, 6, '', ('93.184.216.34', 0))]):
            mock_response = MagicMock()
            mock_response.encoding = 'utf-8'
            mock_response.iter_content.return_value = [
                b"<html><body><p>Test content</p></body></html>"
            ]
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response
            result = self.enhancer.extract_info("http://test.com")
            self.assertEqual(result, "Test content")

    def test_preprocess_text(self):
        text = "This is a TEST with 123 and !@#."
        result = self.enhancer.preprocess_text(text)
        self.assertEqual(result, "this is a test with and")

    def test_format_for_llm(self):
        info = "This is a very long piece of text " * 100
        result = self.enhancer.format_for_llm(info)
        self.assertTrue(result.startswith("Relevant information: This is a very"))
        self.assertTrue(result.endswith("..."))
        self.assertTrue(len(result) < 550)  # 500 chars + "Relevant information: " + "..."

if __name__ == '__main__':
    unittest.main()