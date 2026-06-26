"""Search engine registry.

Re-exports the public engine classes so callers can do:

    from freedom_search.search_engines import SearchEngine, DuckDuckGoSearch
"""
from freedom_search.search_engines.base import SearchEngine
from freedom_search.search_engines.duckduckgo import DuckDuckGoSearch
from freedom_search.search_engines.google import GoogleSearch

__all__ = [
    "SearchEngine",
    "DuckDuckGoSearch",
    "GoogleSearch",
]
