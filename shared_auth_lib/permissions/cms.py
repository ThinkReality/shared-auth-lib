"""CMS feature permission constants. Scheme: cms:{resource}:{action}.

Ports the content-platform cms landing-page authority that was previously a
`PlatformRole.ADMIN` role gate. `cms` is a Feature-spine member.
"""

CMS_LANDING_PAGE_PUBLISH = "cms:landing_page:publish"

__all__ = [
    "CMS_LANDING_PAGE_PUBLISH",
]
