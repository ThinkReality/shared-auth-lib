# Changelog

All notable changes to shared-auth-lib will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- `AUTH_CONTEXT_REQUEST_TIMEOUT` is now configurable via `AUTH_LIB_AUTH_CONTEXT_REQUEST_TIMEOUT` env var (default 5.0s)
- Added `NullHandler` to package logger (Python library best practice)

### Fixed
- `require_auth` now sets `request.state.auth_context` in the DEV_MODE_BYPASS branch, matching the production code path. Without this, downstream consumers that read `request.state.auth_context` directly (e.g. tenant-session dependencies) returned 401 under dev bypass even though the dep itself resolved successfully.

## [0.4.0] - 2026-06-08

### Added
- `shared_auth_lib.constants.roles`: canonical `PlatformRole` (9 system roles),
  `ADMIN_ROLES`, `AGENT_ROLES`, `ROLE_RANK`. Phantom `TENANT_ADMIN` is excluded.
- `shared_auth_lib.authz`: `can(ctx, permission, resource=None)` — the single
  authorization entry point (anti-corruption seam for future node-centric RBAC)
  — and `require_capability`, a FastAPI dependency mirroring `require_permission`.
- `shared_auth_lib.permissions.task`: pilot per-feature permission module on the
  `{feature}:{action}` scheme, with a conformance test guarding all future modules.
- Regression test freezing the `AuthContext` wire-field set.

Additive. Per-feature permission constant modules are added with each service's
adoption; `permissions/hr.py` prefix migration is owned by people-finance.

## [0.1.0] - 2025-12-25

### Added
- GatewayHMACMiddleware for HMAC-SHA256 signature verification from API gateway
- IdentityExtractionMiddleware for trusted header extraction (X-User-Id, X-Tenant-ID, etc.)
- AuthContextClient for fetching AuthContext from CRM-backend internal API with circuit breaker
- FastAPI dependencies: `require_auth`, `require_role`, `require_permission`, `require_any_role`, `optional_auth`
- AuthContext model with roles, permissions, tenant info, and role hierarchy
- GatewayIdentityHeaders model for pre-lookup header data
- AuthLibSettings configuration with `AUTH_LIB_` prefix (pydantic-settings)
- Custom exceptions: HMACVerificationError, AuthContextNotFoundError, UnauthorizedError
- Full test suite (76 tests)
