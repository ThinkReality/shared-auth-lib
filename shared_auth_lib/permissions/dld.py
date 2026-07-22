"""DLD (Dubai Land Department) feature permission constants. Scheme: {feature}:{action}.

Ports the live require_permission strings from tr-realty-data-hub.
"""

DLD_SYNC_MANAGE = "dld:sync:manage"
DLD_DATASETS_UPLOAD = "dld:datasets:upload"

__all__ = [
    "DLD_SYNC_MANAGE",
    "DLD_DATASETS_UPLOAD",
]
