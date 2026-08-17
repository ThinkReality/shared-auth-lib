# Changelog

All notable changes to shared-auth-lib will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.33.1] - 2026-08-17

### Fixed
- Internal `tr-shared-lib` pin bumped to `v0.66.3` — carries the JSON-log
  `exc_info=True` traceback fix (previously silently dropped in production
  logs). No code change in this lib; pin-only release required because every
  consumer pins both libs by tag and uv rejects a mismatched `tr-shared-lib`
  pin between a consumer and its `shared-auth-lib` dependency.

## [0.29.0] - 2026-08-09

### Added
- `permissions.TASK_READ_ALL = "task:read_all"` — row-visibility bypass for
  `GET /tasks` in tr-crm-core. Not a route gate: without it, a caller sees only
  tasks they are `assigned_to`, `created_by`, `assigned_by`, or a co-assignee on.

## [0.26.0] - 2026-08-03

### Added
- `AuthContext.enabled_modules: list[str]` — the tenant's entitlement, default `[]`
  (fail-closed). The field freeze is amended, not bypassed: additions are
  deploy-order-safe under `extra="ignore"`, removals and renames still need the
  scheduled coordinated cut.
- `authz.entitlement.is_module_enabled` / `require_module(Feature)` — the gate.
  Raises `AuthorizationError` `AUTHLIB_AUTH_011`. Marks `_required_modules`, never
  `_required_permissions`.
- `AuthLibSettings.DEV_MODULES` + the `X-Dev-Modules` override header. The dev
  bypass and the signed test client both grant all eight modules by default —
  without this every dev request and every integration test 403s.
- `testing.ModuleExemption` + `testing.assert_module_gates(app, {prefix: Feature},
  exempt_prefixes={prefix: ModuleExemption(...)})`. An exempt prefix asserts that no
  route under it resolves an `AuthContext`; the claim is re-verified on every run.

### Changed
- **BREAKING** `PROPERTY_SCRAPING_CACHE_FLUSH` → `SCRAPING_CACHE_FLUSH`, value
  `property:scraping_cache:flush` → `scraping:cache:flush`. The `property` prefix
  existed only because scraping had no `Feature` member; tr-shared-lib 0.59.0
  added one. Consumers need the crm-core catalog migration `auth_0011`.
- Internal `tr-shared-lib` pin → `v0.59.0`.

## [0.25.0] - 2026-08-03

### Changed
- Internal `tr-shared-lib` pin moved `v0.57.0` → `v0.58.0`, which adds the
  `hr.job_posting.archived` event.

  No shared-auth-lib code touched — this release exists so the pin moves in lockstep.
  `uv` honours a git dependency's OWN `[tool.uv.sources]`, so a consumer pinning
  tr-shared-lib `v0.58.0` while this library still pinned `v0.57.0` aborts the whole
  resolution with `conflicting URLs for package tr-shared-lib`.

  Suite green against the new pin: 273 passed.

## [0.24.0] - 2026-08-03

### Changed
- Internal `tr-shared-lib` pin moved `v0.56.0` → `v0.57.0`, which removes the Layer 2
  DB-monitoring pipeline (`PersistenceMiddleware`, the Redis request buffer, the
  `monitoring` schema models, `monitoring/tasks/`, `PrometheusClient`) and the
  `MONITORING_DB_URL` / `MONITORING_ENABLED` settings.

  No shared-auth-lib code touched — this release exists so the pin moves in lockstep.
  `uv` honours a git dependency's OWN `[tool.uv.sources]`, so a consumer pinning
  tr-shared-lib `v0.57.0` while this library still pinned `v0.56.0` aborts the whole
  resolution with `conflicting URLs for package tr-shared-lib`.

  Suite green against the new pin: 273 passed.

## [0.23.0] - 2026-08-03

### Added
- `shared_auth_lib.testing.route_surfaces`: a fleet-wide test guard,
  `assert_route_surfaces(app, spec, exemptions, minimum)`, that classifies every
  mounted route into one of five disjoint auth families (`business`, `site_key`,
  `public`, `s2s`, `webhook`) and fails on an unguarded route, a route on more
  than one family, a gated route under an HMAC-skipped prefix (checked even
  when the route is exempted — an exemption's `surfaces` claim is about family
  membership only, never HMAC coverage), an exemption whose claimed surfaces no
  longer match, a stale exemption, or two route objects producing the same
  method+path label (a duplicate router mount, which would otherwise silently
  drop one route's classification). Every route, finding and exemption key is
  `"{METHOD} {path}"`, never a bare path — two methods on one path are two
  independent routes and a path-only key would collapse them (last-registered
  method silently wins) or let one exemption cover every method at a path;
  websocket routes (no `methods` attribute) label as `"WS {path}"`. Recursive
  dependency walk (bridge dependencies wrap `require_auth` one level down);
  permission/role detection reads only the `_required_permissions` marker
  attribute, set by `require_permission`/`require_any_role` (see below) and by
  service-local gates using the same convention — no closure inspection, so a
  dependency merely closing over a bare vocabulary string cannot be mistaken
  for a gate. `webhook_prefixes` matching goes through `path_is_skipped`, the
  fleet's one prefix-matching rule, not a second `str.startswith`.
  `SurfaceSpec` asserts `public_paths ⊆ hmac_skip_paths` at construction. Also
  exports `FAMILIES`, `RouteExemption`, `SurfaceSpec`, `classify_route`,
  `route_surface_report` from `shared_auth_lib.testing`. Nothing in the fleet
  consumes this yet — per-service wrappers land in a later task.

### Changed
- `require_permission` and `require_any_role` now set a `_required_permissions`
  marker attribute on the dependency callable they return — additive metadata,
  no request-path behavior change. This is the sole hook
  `shared_auth_lib.testing.route_surfaces` reads to detect a permission/role
  gate; it mirrors content-platform's service-local `has_permission`, which
  already used the same attribute.

## [0.22.0] - 2026-08-02

### Changed
- `openapi_security_from_skip_paths` publishes `not_public` paths under a new
  **`ServiceToken`** scheme (`X-Service-Token`) instead of the bearer + gateway
  schemes. Those routes skip the gateway signature and are gated by a service
  token at the route layer, so the previous output named a credential they never
  use — the narrower form of the very defect this helper exists to fix.

## [0.21.1] - 2026-08-02

### Fixed
- `openapi_security_from_skip_paths` now carries the app's `openapi_tags` into
  the generated schema. It previously omitted them, which silently dropped every
  tag description a service had declared on its `FastAPI(...)` call
  (tr-lead-management declares seven). Read off the app rather than added as a
  parameter — a caller cannot forget what it never has to pass.

## [0.21.0] - 2026-08-02

Gateway contract wave (WG'). The fleet's request stack was assembled by hand at
seven call sites and nothing checked the result. Two of the seven had it
**exactly inverted**, invisibly: dev compose sets `AUTH_LIB_DEV_MODE_BYPASS=true`
so nothing failed locally, and not one test in the fleet asserted middleware
order.

### Added
- **`install_standard_middleware`** (`shared_auth_lib.middleware`) — the one
  assembly order, with three `Slot`s (`OUTERMOST`, `BEFORE_HMAC`, `INNERMOST`)
  for a service's own layers. Each slot is justified by exactly one real
  service; there is deliberately no escape hatch.
- **`openapi_security_from_skip_paths`** (`shared_auth_lib.openapi`) — the
  `/docs` security view derived from the enforcement list via `path_is_skipped`.
  Replaces four divergent variants, one of which stamped a blanket `BearerAuth`
  on `/internal/*`, on site-key routes, and on health probes.

### Behaviour changes on adoption — read before bumping a consumer
- **`hmac_redis_client` is REQUIRED.** A default of `None` silently disables
  replay protection, which is exactly how tr-people-finance and
  tr-realty-data-hub shipped without it. Both gain replay protection when they
  adopt. Signed requests carry a microsecond-precision timestamp, so each
  produces a distinct signature and existing suites are unaffected.
- **`setup_monitoring` must be called BEFORE the factory.** That places
  `MetricsMiddleware` innermost, so its histogram measures route handling rather
  than the whole stack. tr-realty-data-hub's latency semantics change.
- **`LoggingMiddleware` always receives `service_name`.** It defaults to
  `"unknown"`, and tr-content-platform and tr-realty-data-hub never passed it —
  their logs were attributed to nobody. Their `service_name` field changes.
- **The OpenAPI helper emits ONE model, not a superset of the old ones.**
  tr-content-platform's schema changes: skipped paths gain an explicit
  `security: []` (rather than an absent key) and the two gateway header schemes
  appear. Reproducing both prior behaviours would have re-created the divergence
  inside the shared function.

### Fixed
- `APIIdempotencyMiddleware` is now installed INSIDE HMAC. Outside it — where
  tr-lead-management had it — it is a denial-of-service primitive: the Redis key
  is claimed with `SET NX` before authentication and 4xx responses are cached for
  24h, so an unsigned POST with a guessed `Idempotency-Key` poisons that key for
  a day.

## [0.20.0] - 2026-08-02

Authorization convergence (W2'). Two authorization systems existed here and
disagreed, while one declared itself the only one: `require_capability` raised
`AuthorizationError` — canonical envelope, error code, traceable — while
`require_permission` next door raised a bare `HTTPException`, whose handler
stamps `HTTP_403` and leaves the reason as free text. **Every
`require_permission` denial in the fleet violated the Response Shapes rule.**

### Changed
- **BREAKING (wire).** All six `raise HTTPException` sites in
  `dependencies/auth_dependencies.py` now raise `tr_shared.exceptions`
  `AuthenticationError` / `AuthorizationError`, under a new `AUTHLIB_` prefix.
  shared-auth-lib is a library with no owning service, so it needs its own
  prefix; `AUTH_` is not a service prefix and collides with the unprefixed
  `AUTH_001` / `FORBIDDEN_001` defaults in `tr_shared.exceptions`.

  | Code | Status | Condition |
  |---|---|---|
  | `AUTHLIB_AUTH_001` | 401 | no user identity on the request |
  | `AUTHLIB_AUTH_002` | 401 | auth context not found / expired |
  | `AUTHLIB_AUTH_003` | 401 | account inactive |
  | `AUTHLIB_AUTH_004` | 403 | account suspended |
  | `AUTHLIB_AUTH_005` | 403 | `require_permission` denied |
  | `AUTHLIB_AUTH_006` | 403 | `require_any_role` denied |
  | `AUTHLIB_AUTH_007` | 403 | `require_capability` denied (previously no code) |
  | `AUTHLIB_AUTH_008` | 403 | HMAC signature headers missing |
  | `AUTHLIB_AUTH_009` | 403 | HMAC signature invalid |
  | `AUTHLIB_AUTH_010` | 403 | HMAC signature replayed |

  The denial reason moves from `error.message` to `error.detail`, and becomes
  identifiable by `code` rather than by substring match:

  ```
  before  {"error": {"message": "Permission required: user:delete", "code": "HTTP_403"}}
  after   {"error": {"message": "Authorization failed", "code": "AUTHLIB_AUTH_005",
                     "detail": "Permission required: user:delete"}}
  ```

- The three HMAC rejections now go through `build_error_envelope` and carry
  `correlation_id`, which they previously omitted. Their codes were
  `HMAC_MISSING_HEADERS` / `HMAC_INVALID_SIGNATURE` / `HMAC_REPLAY` — unprefixed,
  so they honoured no `{PREFIX}_{CATEGORY}_{NUMBER}` contract.

- Internal `tr-shared-lib` pin bumped `v0.55.0` → `v0.56.0`, which is **required**:
  the 401 keeps its `WWW-Authenticate` challenge only because `BaseAPIException`
  now accepts `headers`. This file is the fleet's only producer of that header.

### Added
- `tests/test_no_raw_httpexception.py` — no `raise HTTPException` anywhere under
  `dependencies/` or `authz/`. Guards the rule, not the six converted sites, so a
  new dependency reaching for `HTTPException` fails immediately by file and line.
  Proven red by mutation before being trusted.

### Fixed
- `tests/test_auth_dependencies.py` builds its app with
  `register_exception_handlers`, as every real service does. Without them the app
  fell back to Starlette's renderer, so these tests asserted a body shape no
  service returns — and would have kept passing while the real envelope regressed.

## [0.19.6] - 2026-08-01

### Changed
- Internal `tr-shared-lib` pin bumped `v0.54.0` → `v0.55.0` (no code change in this library).
  `v0.54.0` was an orphan tag — cut on a pre-squash PR commit, never an ancestor of `main`.
  It is left in place, not re-pointed; `v0.55.0` is the forward release that supersedes it.

## [0.19.5] - 2026-08-01

### Changed
- Internal `tr-shared-lib` pin bumped `v0.53.0` → `v0.54.0` (no code change in this
  library).

### Why
`v0.54.0` adds `tr_shared.phone` (behind the new opt-in `phone` extra) for DLD
owner-phone normalisation. This library's pin has to move for consumers to adopt it —
uv honours a git dependency's own `[tool.uv.sources]`, so a mismatch here aborts
every consumer's `uv lock` with `conflicting URLs for package tr-shared-lib`.

### Migration
None. This library does not use `tr_shared.phone` and deliberately does not add the
extra. Consumers move both pins together:
`bash scripts/upgrade-shared-libs.sh v0.54.0 v0.19.5`.

## [0.19.4] - 2026-07-31

### Changed
- Internal `tr-shared-lib` pin bumped `v0.52.0` → `v0.53.0` (no code change in this
  library).

### Why
`v0.53.0` adds G14: the pytest plugin refuses a run whose interpreter belongs to another
service's `.venv`. This library's pin has to move for consumers to adopt it — uv honours a
git dependency's own `[tool.uv.sources]`, so a mismatch here aborts every consumer's
`uv lock` with `conflicting URLs for package tr-shared-lib`.

### Migration
None. Consumers move both pins together:
`bash scripts/upgrade-shared-libs.sh v0.53.0 v0.19.4`.

## [0.19.3] - 2026-07-31

### Changed
- Internal `tr-shared-lib` pin bumped `v0.51.0` → `v0.52.0` (no code change in this
  library).

### Why
uv honours a git dependency's OWN `[tool.uv.sources]`; it is not overridden by the
top-level consumer's. So this library's internal pin must match what consumers pin,
or `uv lock` aborts with `conflicting URLs for package tr-shared-lib`. Cutting this
tag is therefore not optional bookkeeping — it is what makes `tr-shared-lib v0.52.0`
adoptable by anything at all.

`v0.52.0` carries the test-lane fix (a unit-lane run no longer provisions a
container it cannot use) plus a repo-wide ruff reformat. Nothing in this library's
API is affected.

### Migration
None. Consumers move both pins together:
`bash scripts/upgrade-shared-libs.sh v0.52.0 v0.19.3`.

## [0.19.2] - 2026-07-31

### Changed
- Internal `tr-shared-lib` pin bumped `v0.50.0` → `v0.51.0`, for
  `HttpHeader.ORIGINAL_IP` (no code change in this library).

### Why
Pin-only release. `0.19.1` was never cut — the version string never existed in
`pyproject.toml`, so the gap in this file is real history, not a missing entry.

### Migration
None.

## [0.19.0] - 2026-07-30

### Added
- `shared_auth_lib.permissions.wam` — `WAM_SESSION_MANAGE` (`wam:session:manage`),
  `WAM_BROADCAST_READ` (`wam:broadcast:read`), `WAM_BROADCAST_SEND`
  (`wam:broadcast:send`), all re-exported from `shared_auth_lib.permissions` and
  registered in the permission registry.

### Changed
- `tests/test_signed_header_contract.py` now documents the safe procedure for
  changing `SIGNED_HEADERS`, learned when `X-Site-Id` was added: ship the contract
  change alone (a member present but populated by nobody appends the same `""` on
  both sides, so the canonical string is unchanged in practice), then re-pin and
  deploy the gateway and every downstream service **together**, and only then start
  populating the header. Verify the middle step with a live authenticated request
  through the gateway to every service — 200, not 403.

### Why
The prefix is `wam`, not `whatsapp`, because the prefix must be a member of the
Feature spine (`tr_shared.contracts.taxonomy.Feature.WAM`); `tests/test_permissions.py`
rejects anything else. These gate WAM's *gateway* surface only — its S2S routes live
under `/api/v1/internal/` and are gated by `X-Service-Token`, so they carry no
permission.

Despite its commit message, this release adds **no** new signed header:
`constants/headers.py` is untouched. Only the contract test's documentation changed.

### Migration
Additive. WAM consumes these via `require_permission(...)`; no other service is
affected.

## [0.18.6] - 2026-07-30

### Added
- `shared_auth_lib.site_keys.SiteStatus` — `StrEnum` with `ACTIVE = "active"` and
  `SUSPENDED = "suspended"`. The site-status vocabulary now has one definition,
  beside `hash_site_key`, which is the other half of the same producer/verifier
  contract.

### Why
tr-crm-core ISSUES site keys and owns the site lifecycle; tr-api-gateway VERIFIES
them and enforces that lifecycle. The status vocabulary was declared twice — a
`StrEnum` in crm-core's `TenantSite` model, and in the gateway an untyped
`status: str` plus a private `_SITE_STATUS_ACTIVE = "active"`.

The drift is silent in the dangerous direction. Add a third member in crm-core —
`archived`, say — and the gateway compares it against `"active"`, finds it unequal,
and returns **403 "This site is suspended"** for a site that is not suspended. Wrong
reason, no exception, nothing failing at build or test time in either repo.

This is exactly the failure mode `hash_site_key` was moved here to prevent, as that
module's docstring already states: *"Both import from here so the two can never
drift: a mismatch would not raise, it would simply make every key fail to resolve."*
Hashing was made undriftable; the vocabulary travelling on the same wire, in the same
request, between the same two services, was not (A12).

### Migration
None for this library — additive. Consumers that adopt it should type the boundary,
not just import the name: with `ResolvedSite.status: SiteStatus`, a status the
gateway's copy does not know now **raises at validation** instead of being silently
treated as not-active. That is the intended behavior change (A12 Option A): a version
skew between issuer and verifier is a deployment error and should say so, rather than
telling a healthy site it is suspended. It cannot fail open — an unknown status is
never `ACTIVE` under either behaviour.

## [0.18.5] - 2026-07-30

### Changed
- Internal `tr-shared-lib` pin bumped `v0.49.2` → `v0.49.3` (no code change in
  this lib — pin-only bump so downstream consumers pinning the new
  `tr-shared-lib` tag don't hit `conflicting URLs for package tr-shared-lib`).

## [0.18.1] - 2026-07-29

### Changed
- Internal `tr-shared-lib` pin bumped `v0.48.0` → `v0.48.1` (no code change in
  this lib — pin-only bump so downstream consumers pinning the new
  `tr-shared-lib` tag don't hit `conflicting URLs for package tr-shared-lib`).

## [0.18.0] - 2026-07-29

### Changed (BREAKING)
- `AuthLibSettings.ENVIRONMENT` now reads the platform `ENVIRONMENT` variable
  directly (`validation_alias="ENVIRONMENT"`), not `AUTH_LIB_ENVIRONMENT`. Also
  retyped `str` → `Environment` (from `tr_shared.contracts`, pinned `v0.48.0`).
  `AUTH_LIB_ENVIRONMENT` is no longer read anywhere.

### Why
Two variables for one concept let a service's own bypass validator (reading
`ENVIRONMENT`) pass while this library's guard (reading `AUTH_LIB_ENVIRONMENT`)
saw a different value — a split-brain that could silently disagree.

### Migration
Delete `AUTH_LIB_ENVIRONMENT` from every config surface (compose, `.env`,
conftest). Set the platform `ENVIRONMENT` to one of `development`, `test`,
`staging`, `production` — the library now reads that value.

### Note
`AuthLibSettings.model_config` sets `env_file=".env"`, so after this change the
library reads a bare `ENVIRONMENT=` line from whatever `.env` is in CWD — a new
coupling. Benign post-Task-10 (every service's `.env` now carries the canonical
value), but it is a behaviour change worth knowing about.

## [0.17.6] - 2026-07-29

### Changed
- Internal `tr-shared-lib` pin moved to `v0.48.0` (`BaseServiceSettings.ENVIRONMENT`
  is now typed `Environment`, not `str` — see that release's notes). No behaviour
  change in this library.

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
