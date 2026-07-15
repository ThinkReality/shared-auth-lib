"""Logging for shared-auth-lib.

Uses structlog so that log output integrates with whatever structlog
configuration the consuming service has set up.

Integration contract
--------------------
This module does NOT configure structlog handlers or processors.
That is the consuming service's responsibility.
Services must call ``tr_shared.logging.configure_logging()`` during
startup to get structured JSON output in production.
"""

from typing import cast

import structlog


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a named structlog logger for shared-auth-lib modules."""
    return cast("structlog.stdlib.BoundLogger", structlog.get_logger(name))
