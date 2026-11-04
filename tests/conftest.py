"""Shared test fixtures for shared-auth-lib."""

import os

from tr_shared.testing.config import POLICY_ENV

for key, value in POLICY_ENV.items():
    os.environ.setdefault(key, value)
