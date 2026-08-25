# Handoff: Roles Model Implementation

## Session Metadata
- Created: 2026-08-25 18:20:30
- Project: /home/cricro/projects/UNSAReport/auth
- Branch: dev

## Handoff Chain
- **Continues from**: [2026-08-25-175639-idp-oidc-jwks-architecture-implementation.md](file:///home/cricro/projects/UNSAReport/auth/.agents/handoffs/2026-08-25-175639-idp-oidc-jwks-architecture-implementation.md)
- **Supersedes**: [2026-08-25-175639-idp-oidc-jwks-architecture-implementation.md](file:///home/cricro/projects/UNSAReport/auth/.agents/handoffs/2026-08-25-175639-idp-oidc-jwks-architecture-implementation.md)

## Current State Summary

Completed the full implementation of the **Roles Model Technical Plan** for the UNSAReport Identity Provider. Extended database schema with `user_roles` table (with composite unique constraint and composite index), updated JWT access tokens to embed sub-app role mappings (`roles: Record<string, Role>`), updated auth middleware to expose roles on context for JWT and PAT requests, and added role management CRUD routes (`POST /auth/roles`, `DELETE /auth/roles`, `GET /auth/roles/me`, `GET /auth/roles/:subApp`, `GET /auth/roles/user/:userId`) with sub-app admin authorization and `X-Admin-Key` super-admin bypass logic. All 32 unit and E2E integration tests pass, and Biome strict check passes with 0 errors and 0 warnings.

## Codebase Understanding

### Architecture Overview

- **IDP Server**: Hono app running on Bun serving identity, OAuth, PAT, and role management.
- **Roles Storage**: Binary per-sub-app role model (`'user'` | `'admin'`) stored in `user_roles` Postgres table.
- **JWT Roles Claims**: Access tokens signed using RS256 contain a JSON object claim `roles: { "sub-app-name": "admin" }` so sub-apps verify caller permissions offline.
- **PAT Roles Resolution**: PATs do not embed JWT claims; auth middleware resolves user roles dynamically via DB lookup (`getUserRoles(userId)`).
- **Admin Authorization**: Role modification endpoints inspect caller's target sub-app role (`callerRoles[subApp] === 'admin'`) or accept `X-Admin-Key` header bypass matching `ADMIN_API_KEY`.

### Critical Files

| File | Purpose | Relevance |
|------|---------|-----------|
| [src/db/schema.ts](file:///home/cricro/projects/UNSAReport/auth/src/db/schema.ts) | Drizzle ORM schema defining `userRoles` table | Database schema |
| [src/types.ts](file:///home/cricro/projects/UNSAReport/auth/src/types.ts) | TypeScript definitions for `Role`, `UserPayload`, `AccessTokenClaims` | Type definitions |
| [src/lib/jwt.ts](file:///home/cricro/projects/UNSAReport/auth/src/lib/jwt.ts) | `getUserRoles(userId)` helper and RS256 token signing with embedded `roles` claim | Token signing & role query |
| [src/middleware/auth.ts](file:///home/cricro/projects/UNSAReport/auth/src/middleware/auth.ts) | Auth middleware attaching `roles` to Hono context for JWT & PAT requests | Protected endpoints |
| [src/routes/auth.ts](file:///home/cricro/projects/UNSAReport/auth/src/routes/auth.ts) | OAuth callback & refresh token rotation with roles, `/auth/me` returning roles | Auth endpoints |
| [src/routes/roles.ts](file:///home/cricro/projects/UNSAReport/auth/src/routes/roles.ts) | Role management CRUD routes & authorization handlers | Role management |
| [src/index.ts](file:///home/cricro/projects/UNSAReport/auth/src/index.ts) | Main Hono app mounting `rolesApp` and health check endpoints list | Server entry point |

### Key Patterns Discovered

- **Sub-App Role Isolation**: Roles are free-form string keys (`subApp`) mapping to `'user'` or `'admin'`. No role hierarchy.
- **Upsert Semantics**: Role assignment `POST /auth/roles` uses ON CONFLICT DO UPDATE on `(userId, subApp)`.
- **Super-Admin Bypass**: `X-Admin-Key` header matching `ADMIN_API_KEY` bypasses role-based authorization for administrative operations (bootstrap & key rotation).

## Work Completed

### Tasks Finished

- [x] Schema: Defined `userRoles` table in `src/db/schema.ts` with composite unique constraint and composite index on `(userId, subApp)`.
- [x] Migration: Applied database migration via `bunx drizzle-kit push`.
- [x] Types: Added `Role` type, updated `UserPayload` and `AccessTokenClaims` in `src/types.ts`.
- [x] JWT: Added `getUserRoles(userId)` helper and embedded `roles` claim in `signAccessToken()` in `src/lib/jwt.ts`.
- [x] Middleware: Updated `authMiddleware` in `src/middleware/auth.ts` to attach `roles` to Hono context for both JWT and PAT requests.
- [x] Call Sites: Updated OAuth callback, refresh token rotation, and `GET /auth/me` in `src/routes/auth.ts` to include roles.
- [x] Roles API: Implemented `POST /auth/roles`, `DELETE /auth/roles`, `GET /auth/roles/me`, `GET /auth/roles/:subApp`, and `GET /auth/roles/user/:userId` in `src/routes/roles.ts`.
- [x] Health Check: Mounted `rolesApp` and added role endpoints to health check list in `src/index.ts`.
- [x] Test Suite: Created `tests/roles.test.ts` covering all 11 role management & integration scenarios. Total test suite expanded to 32 tests (100% passing).
- [x] Biome Audit: Formatted codebase with `bunx biome format --write` and verified strict check with `bunx biome check` (0 errors, 0 warnings).

### Files Modified

| File | Changes | Rationale |
|------|---------|-----------|
| [src/db/schema.ts](file:///home/cricro/projects/UNSAReport/auth/src/db/schema.ts) | Added `userRoles` table, composite unique constraint, and composite index | Roles table schema |
| [src/types.ts](file:///home/cricro/projects/UNSAReport/auth/src/types.ts) | Added `Role` type, updated `UserPayload` and `AccessTokenClaims` | Roles type definitions |
| [src/lib/jwt.ts](file:///home/cricro/projects/UNSAReport/auth/src/lib/jwt.ts) | Added `getUserRoles()`, updated `signAccessToken()` to include `roles` | JWT roles claim |
| [src/middleware/auth.ts](file:///home/cricro/projects/UNSAReport/auth/src/middleware/auth.ts) | Extended `ContextVariableMap`, set `roles` in context for JWT & PAT | Middleware roles injection |
| [src/routes/auth.ts](file:///home/cricro/projects/UNSAReport/auth/src/routes/auth.ts) | Fetch roles before token issuance in OAuth & refresh, return roles in `/auth/me` | Token issuance update |
| [src/routes/roles.ts](file:///home/cricro/projects/UNSAReport/auth/src/routes/roles.ts) | Created role management CRUD endpoints & authorization logic | Role CRUD routes |
| [src/index.ts](file:///home/cricro/projects/UNSAReport/auth/src/index.ts) | Mounted `rolesApp`, added role endpoints to root health check | App entry update |
| [tests/roles.test.ts](file:///home/cricro/projects/UNSAReport/auth/tests/roles.test.ts) | Created 11 automated test cases for role management & token integration | Unit/E2E test suite |

### Decisions Made

| Decision | Options Considered | Rationale |
|----------|-------------------|-----------|
| Composite Unique Index on `(userId, subApp)` | Multiple roles vs Binary single role | Simple binary model (`user` \| `admin`) per user per sub-app |
| Super-Admin `X-Admin-Key` Bypass | Hardcoded seed vs API Key bypass | Solves first-admin bootstrap problem seamlessly using existing rotation key mechanism |
| JWT Embedded Roles | Real-time DB lookup vs JWT claim | Enables external sub-applications to verify roles offline without hitting IDP database |

## Pending Work

### Immediate Next Steps

1. Integrate sub-applications (e.g. `npm-registry`, `slides`) to consume the `roles` object embedded in access tokens.
2. Deploy IDP service updates to staging/production environments.
3. Configure production sub-app admin user assignments using `X-Admin-Key` bootstrapping via `POST /auth/roles`.

### Blockers/Open Questions

- None. All planned feature requirements and test cases are implemented and passing.

### Deferred Items

- Role hierarchy or custom fine-grained permissions array per sub-app (currently handled via PAT `scopes` array and binary sub-app roles).

## Context for Resuming Agent

### Important Context

- **Database**: PostgreSQL container `idp-postgres` running on port 5432. Connect using `DATABASE_URL=postgresql://idp:idppassword@localhost:5432/idp_db`.
- **Test Suite**: Execute `bun test` to run all 32 unit and E2E integration tests.
- **Linter & Formatter**: Run `bunx biome check` to verify code quality. Currently 100% clean (0 errors, 0 warnings).
- **Super-Admin Key**: Pass `X-Admin-Key` header matching `ADMIN_API_KEY` in `.env` to bypass role checks for role management endpoints.

### Assumptions Made

- `subApp` identifiers are free-form strings managed by sub-application conventions (e.g. `'npm-registry'`, `'slides'`).
- Deleting a user cascades and automatically deletes all assigned roles (`onDelete: 'cascade'`).

### Potential Gotchas

- Sub-apps using PAT authentication will not receive roles in a JWT payload; sub-apps should call `GET /auth/roles/me` using the PAT or inspect roles attached in `/auth/me`.

## Environment State

### Tools/Services Used

- Bun v1.3.13
- Docker (PostgreSQL 16 Alpine container on port 5432)
- Biome v2.5.10
- Drizzle ORM v0.45.2 & Drizzle Kit v0.31.10

### Active Processes

- PostgreSQL container `idp-postgres` running on port 5432.

### Environment Variables

- `DATABASE_URL`
- `ADMIN_API_KEY`
- `IDP_ISSUER`
- `IDP_PORT`
- `ACCESS_TOKEN_TTL`
- `REFRESH_TOKEN_TTL`

## Related Resources

- [src/db/schema.ts](file:///home/cricro/projects/UNSAReport/auth/src/db/schema.ts)
- [src/routes/roles.ts](file:///home/cricro/projects/UNSAReport/auth/src/routes/roles.ts)
- [tests/roles.test.ts](file:///home/cricro/projects/UNSAReport/auth/tests/roles.test.ts)
