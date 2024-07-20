import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
from freedom_search.search_engines.base import SearchEngine

class DuckDuckGoSearch(SearchEngine):
    def __init__(self):
        self.search_url = "https://html.duckduckgo.com/html/"

    def search(self, query, num_results=5):
        encoded_query = quote_plus(query)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.get(f"{self.search_url}?q={encoded_query}", headers=headers)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        results = []
        for result in soup.find_all('div', class_='result')[:num_results]:
            title_elem = result.find('h2', class_='result__title')
            snippet_elem = result.find('a', class_='result__snippet')
            
            if title_elem and snippet_elem:
                title = title_elem.text.strip()
                url = title_elem.find('a')['href']
                snippet = snippet_elem.text.strip()
                results.append({
                    'title': title,
                    'url': url,
                    'snippet': snippet
                })
        
        return results
