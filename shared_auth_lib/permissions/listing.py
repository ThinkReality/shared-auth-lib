"""Listing feature permission constants. Scheme: {feature}:{action}.

Ports the live strings from tr-content-platform's local ListingPermissions class
(which this module replaces). The ``listing:*`` wildcard the local class also
declared is intentionally NOT ported — wildcards are grant-side data, not lib
constants.
"""

LISTING_VIEW = "listing:read"
LISTING_CREATE = "listing:create"
LISTING_UPDATE = "listing:update"
LISTING_DELETE = "listing:delete"
LISTING_METRICS_READ = "listing:metrics:read"

__all__ = [
    "LISTING_CREATE",
    "LISTING_DELETE",
    "LISTING_METRICS_READ",
    "LISTING_UPDATE",
    "LISTING_VIEW",
]
