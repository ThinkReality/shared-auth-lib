"""tr-whatsApp-marketing-agent permission constants. Scheme: wam:{resource}:{action}.

The prefix is `wam` because that is the Feature-spine member
(tr_shared.contracts.taxonomy.Feature.WAM). `whatsapp` is not a Feature and
tests/test_permissions.py rejects it.

Gates WAM's gateway surface. Its S2S routes live under /api/v1/internal/ and are
gated by X-Service-Token instead — they carry no permission.
"""

WAM_SESSION_MANAGE = "wam:session:manage"

WAM_BROADCAST_READ = "wam:broadcast:read"
WAM_BROADCAST_SEND = "wam:broadcast:send"

__all__ = [
    "WAM_SESSION_MANAGE",
    "WAM_BROADCAST_READ",
    "WAM_BROADCAST_SEND",
]
