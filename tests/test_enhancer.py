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
        mock_time.side_effect = [0, 0.5]  # First call returns 0, second call returns 0.5
        self.enhancer._rate_limit()
        mock_sleep.assert_called_once_with(0.5)  # Should sleep for 0.5 seconds

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
        with patch('freedom_search.enhancer.requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.text = "<html><body><p>Test content</p></body></html>"
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