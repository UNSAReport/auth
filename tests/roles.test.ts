import { beforeAll, describe, expect, test } from 'bun:test';
import { config } from '@/config';
import { db } from '@/db/index';
import { type User, users } from '@/db/schema';
import app from '@/index';
import { getUserRoles, signAccessToken, verifyAccessToken } from '@/lib/jwt';

interface RoleItem {
  id: string;
  userId: string;
  subApp: string;
  role: string;
}

describe('Role Management Endpoints & Integration', () => {
  let userA: User;
  let userB: User;
  let jwtTokenUserB: string;

  beforeAll(async () => {
    const [uA] = await db
      .insert(users)
      .values({
        email: `roles_user_a_${Date.now()}@unsareport.org`,
        name: 'User A',
      })
      .returning();
    userA = uA;

    const [uB] = await db
      .insert(users)
      .values({
        email: `roles_user_b_${Date.now()}@unsareport.org`,
        name: 'User B',
      })
      .returning();
    userB = uB;

    jwtTokenUserB = await signAccessToken({
      sub: userB.id,
      email: userB.email,
      name: userB.name,
      roles: {},
    });
  });

  test('1. Assign role to user — success', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/auth/roles', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Key': config.adminApiKey,
        },
        body: JSON.stringify({
          userId: userA.id,
          subApp: 'npm-registry',
          role: 'admin',
        }),
      }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.role.userId).toBe(userA.id);
    expect(body.role.subApp).toBe('npm-registry');
    expect(body.role.role).toBe('admin');
  });

  test('2. Assign role — duplicate (upsert updates role)', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/auth/roles', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Key': config.adminApiKey,
        },
        body: JSON.stringify({
          userId: userA.id,
          subApp: 'npm-registry',
          role: 'admin',
        }),
      }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.role.role).toBe('admin');
  });

  test('3. Revoke role — success', async () => {
    await app.fetch(
      new Request('http://localhost:3000/auth/roles', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Key': config.adminApiKey,
        },
        body: JSON.stringify({
          userId: userB.id,
          subApp: 'slides',
          role: 'user',
        }),
      }),
    );

    const res = await app.fetch(
      new Request('http://localhost:3000/auth/roles', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Key': config.adminApiKey,
        },
        body: JSON.stringify({
          userId: userB.id,
          subApp: 'slides',
        }),
      }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
  });

  test('4. Revoke role — not found', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/auth/roles', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Key': config.adminApiKey,
        },
        body: JSON.stringify({
          userId: userB.id,
          subApp: 'non-existent-app',
        }),
      }),
    );

    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBe('Not Found');
  });

  test('5. List roles for sub-app — returns all users with roles', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/auth/roles/npm-registry', {
        headers: {
          'X-Admin-Key': config.adminApiKey,
        },
      }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.subApp).toBe('npm-registry');
    expect(Array.isArray(body.roles)).toBe(true);
    expect(body.roles.some((r: RoleItem) => r.userId === userA.id)).toBe(true);
  });

  test('6. List roles for user — returns all sub-app roles', async () => {
    const res = await app.fetch(
      new Request(`http://localhost:3000/auth/roles/user/${userA.id}`, {
        headers: {
          'X-Admin-Key': config.adminApiKey,
        },
      }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.userId).toBe(userA.id);
    expect(Array.isArray(body.roles)).toBe(true);
    expect(
      body.roles.some(
        (r: RoleItem) => r.subApp === 'npm-registry' && r.role === 'admin',
      ),
    ).toBe(true);
  });

  test('7. Non-admin attempting admin operation — 403', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/auth/roles', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${jwtTokenUserB}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId: userB.id,
          subApp: 'npm-registry',
          role: 'user',
        }),
      }),
    );

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe('Forbidden');
  });

  test('8. Admin-key bypass — success', async () => {
    const res = await app.fetch(
      new Request('http://localhost:3000/auth/roles', {
        method: 'POST',
        headers: {
          'X-Admin-Key': config.adminApiKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId: userB.id,
          subApp: 'analytics',
          role: 'admin',
        }),
      }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
  });

  test('9. Roles appear in JWT after assignment', async () => {
    const rolesA = await getUserRoles(userA.id);
    const token = await signAccessToken({
      sub: userA.id,
      email: userA.email,
      name: userA.name,
      roles: rolesA,
    });

    const verified = await verifyAccessToken(token);
    expect(verified.roles).toBeDefined();
    expect(verified.roles['npm-registry']).toBe('admin');
  });

  test('10. /auth/me returns roles', async () => {
    const rolesA = await getUserRoles(userA.id);
    const updatedTokenUserA = await signAccessToken({
      sub: userA.id,
      email: userA.email,
      name: userA.name,
      roles: rolesA,
    });

    const res = await app.fetch(
      new Request('http://localhost:3000/auth/me', {
        headers: { Authorization: `Bearer ${updatedTokenUserA}` },
      }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.roles).toBeDefined();
    expect(body.roles['npm-registry']).toBe('admin');
  });

  test('11. /auth/roles/me returns current user roles', async () => {
    const rolesA = await getUserRoles(userA.id);
    const updatedTokenUserA = await signAccessToken({
      sub: userA.id,
      email: userA.email,
      name: userA.name,
      roles: rolesA,
    });

    const res = await app.fetch(
      new Request('http://localhost:3000/auth/roles/me', {
        headers: { Authorization: `Bearer ${updatedTokenUserA}` },
      }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.roles).toBeDefined();
    expect(body.roles['npm-registry']).toBe('admin');
  });
});
