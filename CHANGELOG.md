# Changelog

All notable changes to shared-auth-lib will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.17.5] - 2026-07-29

### Changed
- Internal `tr-shared-lib` pin moved to `v0.47.0` (adds `tr_shared.testing.transaction_guard`
  and `tr_shared.testing.stubs`). No behaviour change in this library.

## [0.17.2] - 2026-07-28

### Changed
- Internal `tr-shared-lib` pin moved to `v0.45.0` (adds `tr_shared.testing`, the
  fleet-wide raw `X-Tenant-ID` header guard). No behaviour change in this library.

### Notes
- The pin must move in lockstep with consumers. `uv` honours a git dependency's own
  `[tool.uv.sources]`, so a consumer on `tr-shared-lib v0.45.0` against a
  `shared-auth-lib` still pinning `v0.44.0` aborts with
  `conflicting URLs for package tr-shared-lib`. That is why this release exists.

## [0.17.1] - 2026-07-27

### Changed
- Internal `tr-shared-lib` pin moved to `v0.44.0` (the `Environment` vocabulary
  SSOT release). No behaviour change in this library.

### Why
uv honours a git dependency's own `[tool.uv.sources]`, so a consumer pinning
`tr-shared-lib v0.44.0` while this library still pinned `v0.43.0` aborts with
`conflicting URLs for package tr-shared-lib`. Every tr-shared-lib bump therefore
requires a matching shared-auth-lib release in the same step.

## [0.17.0] - 2026-07-27

### Changed
- `optional_auth` now rejects inactive and suspended accounts (returns `None`,
  matching an unauthenticated caller) and sets `request.state.auth_context`,
  mirroring `require_auth`. Takes a `request: Request` parameter — a signature
  change, but FastAPI injects it, so no call site changes.
- `constants/roles.py` and `AuthContext.has_any_role` docs corrected: both
  system roles are **per-tenant** rows (`auth_roles.tenant_id` is NOT NULL), so
  a role name confers no cross-tenant scope and must never gate tenant scope.
  These comments were the upstream SSOT of the cross-tenant leak being removed
  in the tenant-isolation remediation.
- Internal `tr-shared-lib` pin `v0.42.1` → `v0.43.0`.

### Fixed
- `__version__` was stuck at `0.16.0` while `pyproject.toml` said `0.16.1`,
  failing `test_version_parity`. Both now read `0.17.0`.

## [0.16.0] - 2026-07-26

### Removed (BREAKING)
- `AuthContext.has_role()` — widened role checks via `role_hierarchy`, returning
  True for a role held only through the `parent_role_id` ancestor chain. Every
  caller was a cross-tenant scope gate, the one place inheritance must not
  apply, so it could only ever loosen a boundary it was never meant to touch.
  Use `has_any_role([role])`, the exact check.
- `AuthContext.role_hierarchy` field — existed solely to feed `has_role`.
  Dropped from the frozen wire contract (13 → 12 fields).
- `require_role()` — resolved through `has_role`; had zero callers fleet-wide
  (every service already used `require_any_role`). Use `require_any_role([role])`.

### Migration
- Replace `ctx.has_role(X)` with `ctx.has_any_role([X])` and `require_role(X)`
  with `require_any_role([X])`. On a role graph with no `parent_role_id` links
  the two are equivalent, so this is behaviour-preserving unless role
  inheritance is in use — in which case the old call was granting cross-tenant
  access it should not have.
- **No coordinated rollout needed.** `AuthContext` uses Pydantic's default
  `extra="ignore"`: a producer still sending `role_hierarchy` is tolerated, and
  a consumer on an older lib falls back to the field default. Compatible in
  both directions, in any deploy order.
- Producers may stop populating `role_hierarchy` (tr-crm-core drops its
  recursive `parent_role_id` CTE). The `Role.parent_role_id` column is retained.

## [0.10.0] - 2026-07-23

### Changed (BREAKING)
- `PlatformRole` (9 UPPER members) → `SystemRole` (2 lowercase: `super_admin`,
  `admin`). All non-system roles are per-tenant dynamic data. Removed
  `ADMIN_ROLES`, `AGENT_ROLES`, `ROLE_RANK`; added `SYSTEM_ROLES` frozenset.
- `require_role`/`require_any_role` validate against `SystemRole` (role-name
  gates may reference only the two system roles; feature access is permission-based).
- `DEV_ROLES` default lowercased to `["admin"]`.
- `has_role` (inherited via role_hierarchy) vs `has_any_role` (exact, no
  widening) documented; behavior unchanged. (`has_role` removed in 0.16.0.)

### Migration
- Consumers replace `PlatformRole`→`SystemRole`, `ADMIN_ROLES`→`SYSTEM_ROLES`
  (MANAGER dropped from the admin tier), and re-case any UPPER role literals /
  seeded `Role.name` to lowercase. See tr-api-gateway (P6b) + tr-crm-core (P6c).

## [0.9.2] - 2026-07-22

### Added
- `permissions/cms.py` — `CMS_LANDING_PAGE_PUBLISH` (`cms:landing_page:publish`).
- `lead.LEAD_NOTE_DELETE`, `lead.LEAD_DOCUMENT_DELETE`,
  `lead.LEAD_MINE_POOL_ADMIN_VIEW`; `listing.LISTING_METRICS_READ`.
- All registered in `ALL_PERMISSIONS` + flat-exported. These back the P4
  role-gate→permission migrations in tr-content-platform + tr-lead-management.

## [0.9.1] - 2026-07-22

### Changed
- `permissions.auth` constants renamed to `AUTH_*` (e.g. `USER_CREATE` →
  `AUTH_USER_CREATE`) — string values unchanged (`auth:*`) — and flat-exported
  from `shared_auth_lib.permissions`, so `auth` matches every other domain
  module's naming + export convention. Consumers import
  `from shared_auth_lib.permissions import AUTH_USER_CREATE`.

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
