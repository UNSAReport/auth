# Handoff: IDP + OIDC/JWKS Architecture Plan Implementation & Strict Biome Setup

## Session Metadata
- Created: 2026-08-25 17:56:39
- Project: /home/cricro/projects/UNSAReport/auth
- Branch: dev
- Session duration: ~60 minutes

### Recent Commits (for context)
  - 56a364a feat: implement
  - 674614a chore: init repo

## Handoff Chain

- **Continues from**: None (fresh start)
- **Supersedes**: None

> This is the first handoff for this task.

## Current State Summary

Completed the full implementation of the IDP + OIDC/JWKS Architecture Plan in Bun + Hono + Drizzle ORM (PostgreSQL), along with strict Biome linter/formatter configuration. The server handles Google & GitHub OAuth authentication, RS256 JWT signing, public JWKS endpoint serving, key rotation, session refresh token rotation/revocation, PAT (Personal Access Token) management with audit tracking, and protected user endpoints. All 21 unit/E2E integration tests pass, and Biome strict check passes with 0 errors and 0 warnings.

## Codebase Understanding

### Architecture Overview

- **IDP Server**: Hono app running on Bun.
- **Database**: PostgreSQL (managed via Drizzle ORM). Docker container `idp-postgres` running on port 5432.
- **Asymmetric JWT Signing**: Access tokens signed using RS256 with dynamic RSA 2048-bit keys stored in `signing_keys` table. Header includes `kid` (Key ID).
- **Public JWKS**: Endpoint `GET /.well-known/jwks.json` exports all active public keys in JWK format so external sub-apps can verify JWT signatures offline.
- **Key Rotation**: `POST /auth/keys/rotate` deactivates current key, generates a new RSA key pair, and retains historical keys in database for verifying active tokens signed prior to rotation.
- **Dual Authentication Middleware**: `src/middleware/auth.ts` inspects `Authorization: Bearer <token>`. If prefixed with `unsareport_pat_`, validates as PAT; otherwise verifies RS256 JWT access token.

### Critical Files

| File | Purpose | Relevance |
|------|---------|-----------|
| `src/index.ts` | Main Hono app entry, CORS, startup key initialization | Core entry point |
| `src/db/schema.ts` | Drizzle ORM schema for `users`, `oauth_accounts`, `refresh_tokens`, `personal_access_tokens`, `signing_keys` | Database schema |
| `src/lib/jwt.ts` | RS256 JWT token signing & verification with `kid` lookup | Authentication logic |
| `src/lib/keys.ts` | RSA 2048 key pair generation, key lookup, rotation, & JWKS formatting | Security & Key management |
| `src/lib/tokens.ts` | Refresh token issuance/rotation/revocation & PAT management | Token management |
| `src/lib/oauth.ts` | OAuth provider abstraction (Google & GitHub) & user upsert logic | OAuth integration |
| `src/middleware/auth.ts` | Auth middleware verifying both JWT and PAT tokens | Protected route middleware |
| `biome.json` | Strict Biome linter and formatter configuration | Code quality tool |

### Key Patterns Discovered

- **Standard Token Prefixes**: Refresh tokens start with `unsareport_rf_`; PAT tokens start with `unsareport_pat_`.
- **SHA-256 Storage**: Raw refresh tokens and PATs are returned to the user only once upon creation; stored in database as SHA-256 hashes (`token_hash`).
- **OAuth Provider Registry**: `OAuthProviderRegistry` allows registering new OAuth providers (Google, GitHub, etc.) dynamically.

## Work Completed

### Tasks Finished

- [x] Phase 1: Database schema definition in Drizzle ORM & Postgres migration (`drizzle-kit push`).
- [x] Phase 1: Google OAuth flow (redirect, callback, user upserting).
- [x] Phase 1: RS256 JWT signing & verification library using `jose`.
- [x] Phase 1: Public JWKS endpoint (`GET /.well-known/jwks.json`).
- [x] Phase 1: Opaque refresh token issuance, rotation, and revocation endpoints (`/auth/refresh`, `/auth/logout`).
- [x] Phase 2: PAT create, list, and delete/revoke endpoints (`/auth/pat`).
- [x] Phase 2: Dual authentication middleware supporting both JWT and PAT authentication with `last_used_at` audit logging.
- [x] Phase 3: RSA 2048 key pair generation, active key management, and admin key rotation (`POST /auth/keys/rotate`).
- [x] Phase 4: Extended OAuth provider abstraction with GitHub OAuth provider implementation (`/auth/github`, `/auth/github/callback`).
- [x] Test Suite: 21 automated unit and integration E2E tests in `tests/`.
- [x] Strict Biome Setup: Installed `@biomejs/biome`, configured `biome.json` with strict preset, and resolved all 0 errors / 0 warnings.

### Files Modified

| File | Changes | Rationale |
|------|---------|-----------|
| `package.json` | Added `drizzle-orm`, `postgres`, `jose`, `@biomejs/biome`, `drizzle-kit` | Project dependencies |
| `drizzle.config.ts` | Configured Drizzle Kit for PostgreSQL | Schema migration tooling |
| `biome.json` | Configured strict Biome linter/formatter rules | Code quality enforcement |
| `src/config.ts` | Centralized env configuration | Environment settings |
| `src/types.ts` | Shared TypeScript interfaces | Type definitions |
| `src/db/schema.ts` | Defined 5 Drizzle database tables | Database structure |
| `src/db/index.ts` | Initialized Drizzle Postgres client | DB connection |
| `src/lib/hash.ts` | SHA-256 hashing and random hex helper | Hashing & security |
| `src/lib/keys.ts` | RSA 2048 key generation, active key lookup, rotation, JWKS export | Cryptographic key management |
| `src/lib/jwt.ts` | RS256 JWT signing & verification | JWT handling |
| `src/lib/tokens.ts` | Refresh token and PAT generation/verification/revocation | Token lifecycle |
| `src/lib/oauth.ts` | OAuth provider abstraction (Google & GitHub) & user upsert logic | OAuth integration |
| `src/middleware/auth.ts` | Auth middleware for JWT and PAT tokens | Protected endpoints |
| `src/routes/jwks.ts` | `/.well-known/jwks.json` & `/auth/keys/rotate` routes | JWKS & key rotation |
| `src/routes/auth.ts` | OAuth, refresh, logout, `/auth/me` routes | Main auth endpoints |
| `src/routes/pat.ts` | PAT management CRUD routes | PAT endpoints |
| `src/index.ts` | Main Hono app entry point | Server entry point |
| `tests/*` | 5 test files (`hash`, `keys`, `jwt`, `tokens`, `api`) | Test coverage |

### Decisions Made

| Decision | Options Considered | Rationale |
|----------|-------------------|-----------|
| RS256 Asymmetric JWT | HS256 vs RS256 | Sub-apps verify JWT signature locally via JWKS without database access |
| Opaque Hashed Refresh Tokens | JWT vs Opaque Hashed | Revocable, un-decodable session security |
| Token Prefixes | Raw random vs Prefixed | Scannable in code bases (`unsareport_pat_` and `unsareport_rf_`) |
| `jose` Library | Web Crypto API vs `jose` | Native Web Crypto performance with standard JWKS/JWT export helpers |
| Biome `"preset": "all"` | Standard vs Strict Preset | Comprehensive code formatting, security analysis, and type safety |

## Pending Work

### Immediate Next Steps

1. Run server in development mode using `bun run dev` when testing live requests.
2. Deploy IDP service to production environment and set production OAuth credentials in `.env`.
3. Integrate sub-applications (e.g. npm registry, slides app) by having them fetch `GET /.well-known/jwks.json` for token verification.

### Blockers/Open Questions

- None. All planned features and test cases are implemented and passing.

### Deferred Items

- Scope enforcement granularity for specific PAT actions (DB schema supports `scopes: text[].array()`, currently saved and returned in PAT info for future sub-app authorization checks).

## Context for Resuming Agent

### Important Context

- **Database**: PostgreSQL container `idp-postgres` is active on port 5432. Connect using `DATABASE_URL=postgresql://idp:idppassword@localhost:5432/idp_db`.
- **Test Suite**: Run `bun test` to execute all 21 unit and E2E integration tests.
- **Linter / Formatter**: Run `bunx biome check` to verify code quality. Currently 100% clean (0 errors, 0 warnings).
- **Admin Key Rotation**: Pass `X-Admin-Key` header matching `ADMIN_API_KEY` in `.env` to hit `POST /auth/keys/rotate`.

### Assumptions Made

- Refresh tokens are HttpOnly cookie-enabled and also supported in JSON body/query parameter.
- OAuth redirect client fallback defaults to `http://localhost:5173`.

### Potential Gotchas

- Sub-apps verifying JWTs must parse the `kid` header from the JWT and match it against the keys array returned by `GET /.well-known/jwks.json`.

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
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `IDP_ISSUER`
- `IDP_PORT`
- `IDP_ALLOWED_ORIGINS`
- `ACCESS_TOKEN_TTL`
- `REFRESH_TOKEN_TTL`
- `CLIENT_REDIRECT_URL`
- `ADMIN_API_KEY`

## Related Resources

- [drizzle.config.ts](file:///home/cricro/projects/UNSAReport/auth/drizzle.config.ts)
- [biome.json](file:///home/cricro/projects/UNSAReport/auth/biome.json)
- [src/index.ts](file:///home/cricro/projects/UNSAReport/auth/src/index.ts)

---

**Security Reminder**: Before finalizing, run `validate_handoff.py` to check for accidental secret exposure.
