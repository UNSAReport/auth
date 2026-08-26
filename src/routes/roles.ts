import { and, eq } from 'drizzle-orm';
import type { Context, MiddlewareHandler } from 'hono';
import { Hono } from 'hono';
import { config } from '@/config';
import { db } from '@/db/index';
import { userRoles, users } from '@/db/schema';
import { authMiddleware } from '@/middleware/auth';
import type { Role } from '@/types';

const rolesApp = new Hono();

const rolesAuthMiddleware: MiddlewareHandler = async (c, next) => {
  const adminHeader = c.req.header('X-Admin-Key');
  if (adminHeader && adminHeader === config.adminApiKey) {
    c.set('isSuperAdmin', true);
    c.set('roles', {});
    await next();
    return;
  }
  return authMiddleware(c, next);
};

function authorizeAdminForSubApp(c: Context, subApp: string): boolean {
  if (c.get('isSuperAdmin')) {
    return true;
  }
  const roles = c.get('roles') || {};
  return roles[subApp] === 'admin';
}

function hasAnyAdminRole(c: Context): boolean {
  if (c.get('isSuperAdmin')) {
    return true;
  }
  const roles = c.get('roles') || {};
  return Object.values(roles).includes('admin');
}

// GET /auth/roles/me — convenience endpoint for current user's roles
rolesApp.get('/auth/roles/me', rolesAuthMiddleware, (c) => {
  const roles = c.get('roles') || {};
  return c.json({ roles });
});

// GET /auth/roles/user/:userId — returns all roles for a user
rolesApp.get('/auth/roles/user/:userId', rolesAuthMiddleware, async (c) => {
  const targetUserId = c.req.param('userId');
  const currentUser = c.get('user');

  const isSelf = currentUser && currentUser.id === targetUserId;
  const isAuthorized = isSelf || hasAnyAdminRole(c);

  if (!isAuthorized) {
    return c.json({ error: 'Forbidden', message: 'Requires admin role' }, 403);
  }

  const rows = await db
    .select()
    .from(userRoles)
    .where(eq(userRoles.userId, targetUserId));

  return c.json({ userId: targetUserId, roles: rows });
});

// GET /auth/roles/:subApp — returns all users with roles for a sub-app
rolesApp.get('/auth/roles/:subApp', rolesAuthMiddleware, async (c) => {
  const subApp = c.req.param('subApp');

  if (!authorizeAdminForSubApp(c, subApp)) {
    return c.json({ error: 'Forbidden', message: 'Requires admin role' }, 403);
  }

  const rows = await db
    .select()
    .from(userRoles)
    .where(eq(userRoles.subApp, subApp));

  return c.json({ subApp, roles: rows });
});

// POST /auth/roles — assign or update a user's role for a sub-app
rolesApp.post('/auth/roles', rolesAuthMiddleware, async (c) => {
  const body = await c.req
    .json<{ userId?: string; subApp?: string; role?: Role }>()
    .catch(() => ({}) as { userId?: string; subApp?: string; role?: Role });

  const { userId, subApp, role } = body;

  if (!userId || typeof userId !== 'string') {
    return c.json({ error: 'Bad Request', message: 'userId is required' }, 400);
  }

  if (!subApp || typeof subApp !== 'string' || subApp.trim() === '') {
    return c.json(
      { error: 'Bad Request', message: 'subApp must be a non-empty string' },
      400,
    );
  }

  if (role !== 'user' && role !== 'admin') {
    return c.json(
      { error: 'Bad Request', message: 'role must be "user" or "admin"' },
      400,
    );
  }

  if (!authorizeAdminForSubApp(c, subApp)) {
    return c.json({ error: 'Forbidden', message: 'Requires admin role' }, 403);
  }

  const [targetUser] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId));

  if (!targetUser) {
    return c.json({ error: 'Not Found', message: 'User non-existent' }, 404);
  }

  const [userRole] = await db
    .insert(userRoles)
    .values({ userId, subApp, role })
    .onConflictDoUpdate({
      target: [userRoles.userId, userRoles.subApp],
      set: { role, updatedAt: new Date() },
    })
    .returning();

  return c.json({ success: true, role: userRole });
});

// DELETE /auth/roles — revoke a user's role for a sub-app
rolesApp.delete('/auth/roles', rolesAuthMiddleware, async (c) => {
  const body = await c.req
    .json<{ userId?: string; subApp?: string }>()
    .catch(() => ({}) as { userId?: string; subApp?: string });

  const { userId, subApp } = body;

  if (!userId || typeof userId !== 'string') {
    return c.json({ error: 'Bad Request', message: 'userId is required' }, 400);
  }

  if (!subApp || typeof subApp !== 'string' || subApp.trim() === '') {
    return c.json(
      { error: 'Bad Request', message: 'subApp must be a non-empty string' },
      400,
    );
  }

  if (!authorizeAdminForSubApp(c, subApp)) {
    return c.json({ error: 'Forbidden', message: 'Requires admin role' }, 403);
  }

  const deleted = await db
    .delete(userRoles)
    .where(and(eq(userRoles.userId, userId), eq(userRoles.subApp, subApp)))
    .returning();

  if (deleted.length === 0) {
    return c.json(
      { error: 'Not Found', message: 'Role assignment not found' },
      404,
    );
  }

  return c.json({ success: true, message: 'Role revoked successfully' });
});

export { rolesApp };
