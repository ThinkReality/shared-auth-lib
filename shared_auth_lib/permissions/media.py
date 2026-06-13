"""Media feature permission constants. Scheme: {feature}:{action}.

Ports the live strings from tr-media-service. ``upload`` is a media-specific
action (preferred-verb equivalent: create).
"""

MEDIA_VIEW = "media:read"
MEDIA_UPLOAD = "media:upload"
MEDIA_UPDATE = "media:update"
MEDIA_DELETE = "media:delete"

__all__ = [
    "MEDIA_DELETE",
    "MEDIA_UPDATE",
    "MEDIA_UPLOAD",
    "MEDIA_VIEW",
]
