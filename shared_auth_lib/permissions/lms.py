"""LMS feature permission constants. Scheme: {feature}:{action}.

Ports live strings from tr-lms-service and tr-crm-core learning module.
"""

LMS_AGENT_VIEW_STATS = "lms:agent_view_stats"
LMS_ASSIGNMENT_CREATE = "lms:assignment_create"
LMS_QUIZ_PUBLISH = "lms:quiz_publish"
LMS_QUIZ_VIEW_PROGRESS = "lms:quiz_view_progress"

__all__ = [
    "LMS_AGENT_VIEW_STATS",
    "LMS_ASSIGNMENT_CREATE",
    "LMS_QUIZ_PUBLISH",
    "LMS_QUIZ_VIEW_PROGRESS",
]
