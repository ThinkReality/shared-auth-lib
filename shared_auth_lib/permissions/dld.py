"""DLD (Dubai Land Department) feature permission constants. Scheme: dld:{resource}:{action}.

Ports the live require_permission strings from tr-realty-data-hub's dld module
(sync, dataset uploads, and owner records). Owner permissions were previously
enforced as off-spine `owners:*` strings — canonicalised here under the `dld`
Feature (owners are DLD land-department records); tr-realty-data-hub enforcement
is migrated to these constants in P4.
"""

DLD_SYNC_MANAGE = "dld:sync:manage"
DLD_DATASETS_UPLOAD = "dld:datasets:upload"

DLD_OWNERS_READ = "dld:owners:read"
DLD_OWNERS_CONTACT = "dld:owners:contact"
DLD_OWNERS_IDENTITY = "dld:owners:identity"

__all__ = [
    "DLD_SYNC_MANAGE",
    "DLD_DATASETS_UPLOAD",
    "DLD_OWNERS_READ",
    "DLD_OWNERS_CONTACT",
    "DLD_OWNERS_IDENTITY",
]
