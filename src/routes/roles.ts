import { and, eq } from 'drizzle-orm';
import type { Context, MiddlewareHandler } from 'hono';
import { Hono } from 'hono';
import { config } from '@/config';
import { db } from '@/db/index';
import { userRoles, users } from '@/db/schema';
import { authMiddleware } from '@/middleware/auth';
import type { Role } from '@/types';

const rolesRouter = new Hono();

/**
 * Middleware that authenticates admin requests via X-Admin-Key header or falls back to standard auth middleware.
 *
 * @param c - Hono context object.
 * @param next - Next middleware handler function.
 */
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

/**
 * Checks if the context user is authorized as an administrator for a target sub-app.
 *
 * @param c - Hono context object.
 * @param subApp - Name of the sub-app to check admin authorization for.
 * @returns True if super admin or has admin role for sub-app, false otherwise.
 */
function authorizeAdminForSubApp(c: Context, subApp: string): boolean {
  if (c.get('isSuperAdmin')) {
    return true;
  }
  const roles = c.get('roles') || {};
  return roles[subApp] === 'admin';
}

/**
 * Checks if the context user has an admin role in any sub-app or is a super admin.
 *
 * @param c - Hono context object.
 * @returns True if user possesses any admin role, false otherwise.
 */
function hasAnyAdminRole(c: Context): boolean {
  if (c.get('isSuperAdmin')) {
    return true;
  }
  const roles = c.get('roles') || {};
  return Object.values(roles).includes('admin');
}

/**
 * Route handler for GET /me
 * Returns assigned sub-app roles for the authenticated user.
 */
rolesRouter.get('/me', rolesAuthMiddleware, (c) => {
  const roles = c.get('roles') || {};
  return c.json({ roles });
});

/**
 * Route handler for GET /user/:userId
 * Returns assigned sub-app roles for a specified target user ID.
 */
rolesRouter.get('/user/:userId', rolesAuthMiddleware, async (c) => {
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

/**
 * Route handler for GET /:subApp
 * Returns all user role assignments for a specified sub-app.
 */
rolesRouter.get('/:subApp', rolesAuthMiddleware, async (c) => {
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

/**
 * Route handler for POST /
 * Creates or updates a role assignment for a user in a target sub-app.
 */
rolesRouter.post('/', rolesAuthMiddleware, async (c) => {
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

/**
 * Route handler for DELETE /
 * Revokes a user role assignment for a specified sub-app.
 */
rolesRouter.delete('/', rolesAuthMiddleware, async (c) => {
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

export { rolesRouter };
