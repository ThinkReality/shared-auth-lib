"""Realty scraping-area permission constants. Scheme: scraping:{resource}:{action}.

The live PropertyFinder-scraping operational permission from tr-realty-data-hub.

History, kept deliberately: this was briefly `property:scraping_cache:flush`,
canonicalised under the `property` Feature **because scraping had no spine
member**. tr-shared-lib 0.59.0 added `Feature.SCRAPING` — a tenant can be denied
the scraping module at onboarding, which makes it an entitlement unit, which
under a `frozenset[Feature]` forces it onto the spine. That removed the only
reason for the `property` prefix, so the original string is restored and is now
legitimately on-spine.
"""

SCRAPING_CACHE_FLUSH = "scraping:cache:flush"

__all__ = [
    "SCRAPING_CACHE_FLUSH",
]
