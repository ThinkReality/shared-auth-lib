# Changelog

All notable changes to shared-auth-lib will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-07-22

### Added
- `permissions/auth.py` — auth-domain permission strings, feature-prefixed
  `auth:*` (user/role/credential/credential_type/email + system/audit) so every
  prefix is a `Feature`-spine member (D-PERMSCHEME). crm-core `AuthPermission`
  enum values migrate to these in P2.
- Media billing/usage/quota constants (`media:billing:read`, `media:usage:read`,
  `media:quota:read`, `media:quota:manage`); `admin:webhook:replay`.
- `permissions/dld.py` owner constants under the `dld` Feature
  (`dld:owners:read/contact/identity`, previously off-spine `owners:*`).
- `permissions/scraping.py` `PROPERTY_SCRAPING_CACHE_FLUSH`
  (`property:scraping_cache:flush`, previously off-spine `scraping:cache:flush`).
- `permissions/_registry.py` — `PermissionDef` + `ALL_PERMISSIONS` seedable
  registry (name/resource/action/description) + `permission_names()`. crm-core
  seeds the `auth_permissions` catalog from this in P2.

### Changed
- Auth permission strings canonicalised to the `auth:*` Feature prefix. Consumers
  (crm-core enum values, tr-realty-data-hub enforcement) migrate in P2/P4.

## [0.5.0] - 2026-06-13

### Added
- `__version__` attribute on the package (was absent).
- Per-feature permission modules completing P2-2: `permissions/{lead,listing,
  media,hr,finance}.py` (ported verbatim from live service strings).
  `cms.py` is intentionally NOT shipped — CMS has zero live permission strings
  (role-gated). crm-core-local prefixes (credential/email/user/role/system/
  audit/admin) are out of lib scope.
- Hierarchical wildcard permission matching in `AuthContext.has_permission`
  (`lead:*` grants `lead:read`; `a:b:*` grants `a:b:c`; trailing colon prevents
  `lead:*` leaking to `leads:read`). `can()` and `require_permission` inherit it.
  This is the single platform matcher — services delete their local wildcard
  re-implementations.

### Changed (BREAKING)
- `require_role` / `require_any_role` now validate their role arguments against
  `PlatformRole` at dependency-construction time (router registration). A bare
  or unknown role string raises `ValueError` early instead of silently passing.
  Accept `PlatformRole | str`.
- Permission conformance test relaxed: action token may be a compound
  `[a-z_]+` (e.g. `hr:attendance_read`, `media:upload`), reflecting live
  DB-granted strings; the 8 preferred verbs remain the convention for new
  permissions. Wildcards are forbidden inside lib constants.

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
