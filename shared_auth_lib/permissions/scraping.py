"""Realty scraping-area permission constants. Scheme: property:{resource}:{action}.

Ports the live PropertyFinder-scraping operational permission from
tr-realty-data-hub. Previously enforced as the off-spine `scraping:cache:flush`
string — canonicalised here under the `property` Feature (the scraper produces
property data). The module file stays `scraping.py` (the realty scraping area);
the permission itself is a `property` Feature member. tr-realty-data-hub
enforcement is migrated to this constant in P4.
"""

PROPERTY_SCRAPING_CACHE_FLUSH = "property:scraping_cache:flush"

__all__ = [
    "PROPERTY_SCRAPING_CACHE_FLUSH",
]
