"""Shared test fixtures for shared-auth-lib."""

import os

# Ensure AuthLibSettings can be instantiated during tests
# without requiring real secrets.
os.environ.setdefault("AUTH_LIB_GATEWAY_SIGNING_SECRET", "test-secret")
