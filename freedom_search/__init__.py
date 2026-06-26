"""FreedomSearch — ethical, open-source web intelligence for LLMs."""
from freedom_search.enhancer import (
    InternetSearchEnhancer,
    SearchConfig,
    SearchResult,
)
from freedom_search.search_engines import (
    SearchEngine,
    DuckDuckGoSearch,
    GoogleSearch,
)
from freedom_search.utils import (
    chunk_text,
    deduplicate,
    filter_by_domain,
    hash_query,
    host_of,
    is_internal_ip,
    is_safe_url,
    normalize_url,
    sanitize_text,
)

__all__ = [
    "InternetSearchEnhancer",
    "SearchConfig",
    "SearchResult",
    "SearchEngine",
    "DuckDuckGoSearch",
    "GoogleSearch",
    # Utilities (v0.4)
    "chunk_text",
    "deduplicate",
    "filter_by_domain",
    "host_of",
    "normalize_url",
    # Security utilities (v0.5)
    "hash_query",
    "is_internal_ip",
    "is_safe_url",
    "sanitize_text",
]

__version__ = "0.4.0"
