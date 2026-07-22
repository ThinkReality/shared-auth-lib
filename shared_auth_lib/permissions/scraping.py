"""Scraping feature permission constants. Scheme: {feature}:{action}.

Ports the live require_permission string from tr-realty-data-hub.
"""

SCRAPING_CACHE_FLUSH = "scraping:cache:flush"

__all__ = [
    "SCRAPING_CACHE_FLUSH",
]
