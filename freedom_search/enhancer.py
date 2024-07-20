import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
import re
import time
from functools import lru_cache
from abc import ABC, abstractmethod
from freedom_search.search_engines.duckduckgo import DuckDuckGoSearch
from freedom_search.search_engines.google import GoogleSearch


class InternetSearchEnhancer:
    def __init__(self, search_engine='duckduckgo'):
        self.search_engines = {
            'duckduckgo': DuckDuckGoSearch(),
            'google': GoogleSearch()
        }
        self.set_search_engine(search_engine)
        self.last_request_time = 0
        self.min_request_interval = 1

    def set_search_engine(self, engine):
        if engine not in self.search_engines:
            raise ValueError(f"Unsupported search engine: {engine}")
        self.current_engine = self.search_engines[engine]

    def _rate_limit(self):
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last_request)
        self.last_request_time = time.time()

    @lru_cache(maxsize=100)
    def search(self, query, num_results=5):
        self._rate_limit()
        return self.current_engine.search(query, num_results)

    def extract_info(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            main_content = soup.find('main') or soup.find('article') or soup.find('body')
            if main_content:
                return ' '.join([p.text for p in main_content.find_all('p')])
            return "No content extracted"
        except Exception as e:
            return f"Error extracting info: {str(e)}"

    def preprocess_text(self, text):
        text = text.lower()
        text = re.sub(r'[^a-z\s]', '', text)
        text = ' '.join(text.split())
        return text

    def format_for_llm(self, extracted_info):
        truncated_info = extracted_info[:500] + '...' if len(extracted_info) > 500 else extracted_info
        return f"Relevant information: {truncated_info}"

    def enhance_llm_input(self, original_prompt, search_query):
        results = self.search(search_query)
        if not results:
            return f"{original_prompt}\n\nNote: No additional information found for the search query: '{search_query}'"

        enhanced_info = []
        for result in results:
            info = self.extract_info(result['url'])
            processed_info = self.preprocess_text(info)
            enhanced_info.append(self.format_for_llm(processed_info))

        enhanced_prompt = f"{original_prompt}\n\nAdditional context:\n{' '.join(enhanced_info)}"
        return enhanced_prompt
