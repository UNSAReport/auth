import { beforeAll, describe, expect, test } from 'bun:test';
import { config } from '@/config';
import { db } from '@/db/index';
import { type User, users } from '@/db/schema';
import app from '@/index';
import { signAccessToken } from '@/lib/jwt';
import { createRefreshToken } from '@/lib/tokens';

interface PatItem {
  id: string;
  name: string;
}

describe('IDP API Endpoints E2E', () => {
  let testUser: User;
  let jwtToken: string;
  let refreshToken: string;

  beforeAll(async () => {
    const [u] = await db
      .insert(users)
      .values({
        email: `e2e_user_${Date.now()}@unsareport.org`,
        name: 'E2E User',
        picture: 'https://example.com/avatar.png',
      })
      .returning();
    testUser = u;

    jwtToken = await signAccessToken({
      sub: testUser.id,
      email: testUser.email,
      name: testUser.name,
      picture: testUser.picture,
    });

    refreshToken = await createRefreshToken(testUser.id);
  });

  test('GET / returns API status metadata', async () => {
    const res = await app.fetch(new Request('http://localhost:3000/'));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('online');
    expect(body.issuer).toBe(config.idpIssuer);
  });

  test('GET /v1/.well-known/jwks.json returns public keys', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/v1/.well-known/jwks.json'),
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys.length).toBeGreaterThan(0);
    expect(body.keys[0].kty).toBe('RSA');
  });

  test('POST /v1/auth/keys/rotate rejects unauthorized requests', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/v1/auth/keys/rotate', {
        method: 'POST',
      }),
    );
    expect(res.status).toBe(401);
  });

  test('POST /v1/auth/keys/rotate rotates key with valid admin key', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/v1/auth/keys/rotate', {
        method: 'POST',
        headers: {
          'X-Admin-Key': config.adminApiKey,
        },
      }),
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.key.kid).toBeDefined();
  });

  test('GET /v1/auth/me returns 401 without auth header', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/v1/auth/me'),
    );
    expect(res.status).toBe(401);
  });

  test('GET /v1/auth/me returns user details with valid JWT', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/v1/auth/me', {
        headers: { Authorization: `Bearer ${jwtToken}` },
      }),
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.user.id).toBe(testUser.id);
    expect(body.user.email).toBe(testUser.email);
    expect(body.auth_type).toBe('jwt');
  });

  test('POST /v1/auth/pat creates a new PAT', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/v1/auth/pat', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${jwtToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'CI/CD Token',
          scopes: ['registry'],
        }),
      }),
    );
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.token).toBeDefined();
    expect(body.token.startsWith('unsareport_pat_')).toBe(true);
    expect(body.pat.name).toBe('CI/CD Token');

    const patToken = body.token;
    const patId = body.pat.id;

    const meRes = await app.fetch(
      new Request('http://localhost:3000/v1/auth/me', {
        headers: { Authorization: `Bearer ${patToken}` },
      }),
    );
    expect(meRes.status).toBe(200);
    const meBody = await meRes.json();
    expect(meBody.user.id).toBe(testUser.id);
    expect(meBody.auth_type).toBe('pat');

    const listRes = await app.fetch(
      new Request('http://localhost:3000/v1/auth/pat', {
        headers: { Authorization: `Bearer ${jwtToken}` },
      }),
    );
    expect(listRes.status).toBe(200);
    const listBody = await listRes.json();
    expect(listBody.pats.some((p: PatItem) => p.id === patId)).toBe(true);

    const delRes = await app.fetch(
      new Request(`http://localhost:3000/v1/auth/pat/${patId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${jwtToken}` },
      }),
    );
    expect(delRes.status).toBe(200);
  });

  test('POST /v1/auth/refresh returns new access token and refresh token', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/v1/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      }),
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.access_token).toBeDefined();
    expect(body.refresh_token).toBeDefined();
    expect(body.token_type).toBe('Bearer');
    expect(body.expires_in).toBe(config.accessTokenTtl);
  });

  test('POST /v1/auth/logout revokes refresh token', async () => {
    const newRfToken = await createRefreshToken(testUser.id);
    const logoutRes = await app.fetch(
      new Request('http://localhost:3000/v1/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: newRfToken }),
      }),
    );
    expect(logoutRes.status).toBe(200);

    const refreshRes = await app.fetch(
      new Request('http://localhost:3000/v1/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: newRfToken }),
      }),
    );
    expect(refreshRes.status).toBe(401);
  });
});
