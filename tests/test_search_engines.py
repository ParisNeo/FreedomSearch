import unittest
from unittest.mock import patch, MagicMock
from freedom_search import (
    InternetSearchEnhancer,
    SearchConfig,
    SearchResult,
)
from freedom_search.search_engines.base import SearchEngine


class TestInternetSearchEnhancer(unittest.TestCase):

    def setUp(self):
        self.enhancer = InternetSearchEnhancer()

    def test_init_default_engine(self):
        self.assertIsInstance(
            self.enhancer.current_engine,
            self.enhancer.search_engines['duckduckgo'].__class__,
        )

    def test_set_search_engine_valid(self):
        self.enhancer.set_search_engine('google')
        self.assertIsInstance(
            self.enhancer.current_engine,
            self.enhancer.search_engines['google'].__class__,
        )

    def test_set_search_engine_invalid(self):
        with self.assertRaises(ValueError):
            self.enhancer.set_search_engine('invalid_engine')

    @patch('freedom_search.enhancer.time.sleep')
    @patch('freedom_search.enhancer.time.time')
    def test_rate_limit(self, mock_time, mock_sleep):
        # See original test — preserved exactly.
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
        self.assertTrue(len(result) < 550)

    # ----------------- New tests for v0.3 features -----------------

    def test_custom_config_is_respected(self):
        cfg = SearchConfig(num_results=7, max_extract_chars=42)
        enhancer = InternetSearchEnhancer(config=cfg)
        self.assertIs(enhancer.config, cfg)
        self.assertEqual(enhancer.config.max_extract_chars, 42)

    def test_register_engine_rejects_non_searchengine(self):
        with self.assertRaises(TypeError):
            self.enhancer.register_engine("bad", object())

    def test_register_engine_accepts_searchengine(self):
        class MyEngine(SearchEngine):
            def search(self, query, num_results=5):
                return []

        self.enhancer.register_engine("my", MyEngine())
        self.enhancer.set_search_engine("my")
        self.assertIs(self.enhancer.current_engine,
                      self.enhancer.search_engines["my"])

    def test_search_filters_blocked_domains(self):
        cfg = SearchConfig(blocked_domains=("blocked.com",))
        enhancer = InternetSearchEnhancer(config=cfg)
        enhancer.current_engine = MagicMock()
        enhancer.current_engine.search.return_value = [
            {'title': 'A', 'url': 'http://ok.com/1', 'snippet': ''},
            {'title': 'B', 'url': 'http://blocked.com/1', 'snippet': ''},
            {'title': 'C', 'url': 'http://ok.com/2', 'snippet': ''},
        ]
        enhancer.cache_clear()
        result = enhancer.search("query", num_results=5)
        urls = [r['url'] for r in result]
        self.assertIn("http://ok.com/1", urls)
        self.assertNotIn("http://blocked.com/1", urls)

    def test_search_deduplicates_urls(self):
        enhancer = InternetSearchEnhancer()
        enhancer.current_engine = MagicMock()
        enhancer.current_engine.search.return_value = [
            {'title': 'A', 'url': 'http://x.com/?utm=1', 'snippet': ''},
            {'title': 'A-dup', 'url': 'http://x.com/?utm=2', 'snippet': ''},
            {'title': 'B', 'url': 'http://y.com/', 'snippet': ''},
        ]
        enhancer.cache_clear()
        result = enhancer.search("dedup-query", num_results=5)
        urls = [r['url'] for r in result]
        # Both x.com entries collapse; y.com survives.
        self.assertEqual(len(result), 2)

    def test_extract_parallel_single_url_uses_sequential_path(self):
        enhancer = InternetSearchEnhancer()
        with patch.object(enhancer, "extract_info",
                          return_value="hello") as mock_extract:
            result = enhancer._extract_parallel(["http://x.com"])
        self.assertEqual(result, ["hello"])
        mock_extract.assert_called_once()

    def test_extract_parallel_many_urls_uses_pool(self):
        cfg = SearchConfig(max_workers=2)
        enhancer = InternetSearchEnhancer(config=cfg)
        urls = [f"http://x.com/{i}" for i in range(5)]
        with patch.object(enhancer, "extract_info",
                          side_effect=lambda u: f"content-of-{u}"):
            result = enhancer._extract_parallel(urls)
        self.assertEqual(len(result), 5)
        # Aligned with input order
        for u, r in zip(urls, result):
            self.assertEqual(r, f"content-of-{u}")

    def test_enhance_respects_total_char_budget(self):
        cfg = SearchConfig(max_total_chars=200)
        enhancer = InternetSearchEnhancer(config=cfg)
        enhancer.current_engine = MagicMock()
        enhancer.current_engine.search.return_value = [
            {'title': 'T', 'url': f'http://x.com/{i}', 'snippet': ''}
            for i in range(10)
        ]
        with patch.object(enhancer, "extract_info",
                          return_value="x" * 200):
            enhancer.cache_clear()
            result = enhancer.enhance_llm_input("P", "q")
        # Budget should prevent including all 10 chunks
        self.assertLessEqual(len(result), 200 + len("P\n\nAdditional context:\n") + 100)

    # ----------------- New tests for v0.4 features -----------------

    def test_score_is_computed_per_result(self):
        """Each result from search() must carry a _score in [0, 1]."""
        enhancer = InternetSearchEnhancer()
        enhancer.current_engine = MagicMock()
        enhancer.current_engine.search.return_value = [
            {'title': 'quantum physics article', 'url': 'http://a.com',
             'snippet': 'all about quantum entanglement'},
            {'title': 'cooking recipes', 'url': 'http://b.com',
             'snippet': 'how to bake bread'},
        ]
        enhancer.cache_clear()
        result = enhancer.search("quantum physics", num_results=5)
        scores = [r["_score"] for r in result]
        # First result has term overlap, second does not.
        self.assertGreater(scores[0], 0.0)
        self.assertEqual(scores[1], 0.0)
        # All scores are in [0, 1].
        for s in scores:
            self.assertGreaterEqual(s, 0.0)
            self.assertLessEqual(s, 1.0)

    def test_enhance_sorts_results_by_score_descending(self):
        """enhance_llm_input should pick the highest-scoring result first."""
        enhancer = InternetSearchEnhancer()
        enhancer.current_engine = MagicMock()
        enhancer.current_engine.search.return_value = [
            {'title': 'unrelated stuff', 'url': 'http://a.com', 'snippet': 'x'},
            {'title': 'python programming',
             'url': 'http://b.com', 'snippet': 'python is great'},
        ]
        # Force score ordering: a.com -> 0.0, b.com -> high.
        with patch.object(enhancer, "_score_result",
                          side_effect=lambda r, q: 0.9 if 'b.com' in r['url']
                          else 0.0):
            with patch.object(enhancer, "extract_info",
                              return_value="x" * 50):
                enhancer.cache_clear()
                enhancer.enhance_llm_input("P", "python programming")
                # The high-scoring b.com URL must be fetched first.
                call_args = enhancer.extract_info.call_args_list
                self.assertIn("http://b.com", call_args[0].args[0])

    def test_search_all_merges_results_from_multiple_engines(self):
        """search_all must fan out to every registered engine and merge."""
        # Build two fake engines returning disjoint URLs.
        class EngineA(SearchEngine):
            def search(self, query, num_results=5):
                return [
                    {'title': 'A1', 'url': 'http://a.com/1', 'snippet': 'a1'},
                    {'title': 'SHARED', 'url': 'http://shared.com/x',
                     'snippet': 'shared'},
                ]

        class EngineB(SearchEngine):
            def search(self, query, num_results=5):
                return [
                    {'title': 'B1', 'url': 'http://b.com/1', 'snippet': 'b1'},
                    {'title': 'SHARED', 'url': 'http://shared.com/x',
                     'snippet': 'shared'},
                ]

        enhancer = InternetSearchEnhancer(
            search_engine="a",
            engines={"a": EngineA(), "b": EngineB()},
        )
        enhancer.cache_clear()
        result = enhancer.search_all("any query", num_results=10)
        urls = [r["url"] for r in result]
        # All 3 unique URLs must appear.
        self.assertIn("http://a.com/1", urls)
        self.assertIn("http://b.com/1", urls)
        self.assertIn("http://shared.com/x", urls)
        # SHARED must have the highest score thanks to the vote boost.
        scores = {r["url"]: r["_score"] for r in result}
        self.assertGreater(scores["http://shared.com/x"],
                           scores["http://a.com/1"])

    def test_search_all_handles_engine_failure_gracefully(self):
        """An engine that raises must not abort the whole multi-search."""
        class BoomEngine(SearchEngine):
            def search(self, query, num_results=5):
                raise RuntimeError("kaboom")

        class OkEngine(SearchEngine):
            def search(self, query, num_results=5):
                return [{'title': 'ok', 'url': 'http://ok.com', 'snippet': ''}]

        enhancer = InternetSearchEnhancer(
            search_engine="boom",
            engines={"boom": BoomEngine(), "ok": OkEngine()},
        )
        enhancer.cache_clear()
        result = enhancer.search_all("query", num_results=5)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["url"], "http://ok.com")

    def test_cache_clear_method_exists(self):
        """v0.4 exposes cache_clear() on the enhancer instance."""
        enhancer = InternetSearchEnhancer()
        self.assertTrue(hasattr(enhancer, "cache_clear"))
        # Idempotent: should not raise on an empty cache.
        enhancer.cache_clear()
        enhancer.cache_clear()


if __name__ == '__main__':
    unittest.main()
