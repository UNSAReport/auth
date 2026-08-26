import { eq } from 'drizzle-orm';
import type { MiddlewareHandler } from 'hono';
import { getCookie } from 'hono/cookie';
import { db } from '@/db/index';
import { type PersonalAccessToken, users } from '@/db/schema';
import { getUserRoles, verifyAccessToken } from '@/lib/jwt';
import { verifyPAT } from '@/lib/tokens';
import type { AccessTokenClaims, AuthUser, Role } from '@/types';

declare module 'hono' {
  interface ContextVariableMap {
    user: AuthUser;
    authType: 'jwt' | 'pat';
    pat?: PersonalAccessToken;
    jwtClaims?: AccessTokenClaims;
    roles: Record<string, Role>;
    isSuperAdmin?: boolean;
  }
}

export const authMiddleware: MiddlewareHandler = async (c, next) => {
  const authHeader = c.req.header('Authorization');
  let token: string | undefined;

  if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else {
    token = getCookie(c, 'access_token') || c.req.query('access_token');
  }

  if (!token) {
    return c.json(
      { error: 'Unauthorized', message: 'Missing access token or PAT' },
      401,
    );
  }

  if (token.startsWith('unsareport_pat_')) {
    const patResult = await verifyPAT(token);
    if (!patResult) {
      return c.json(
        { error: 'Unauthorized', message: 'Invalid or revoked PAT' },
        401,
      );
    }
    c.set('user', patResult.user as AuthUser);
    c.set('pat', patResult.pat);
    c.set('authType', 'pat');
    c.set('roles', await getUserRoles(patResult.user.id));
    await next();
    return;
  }

  try {
    const claims = await verifyAccessToken(token);
    const [userRecord] = await db
      .select()
      .from(users)
      .where(eq(users.id, claims.sub));

    if (!userRecord) {
      return c.json(
        { error: 'Unauthorized', message: 'User non-existent' },
        401,
      );
    }

    c.set('user', userRecord as AuthUser);
    c.set('jwtClaims', claims);
    c.set('authType', 'jwt');
    c.set('roles', claims.roles);
    await next();
  } catch (err: unknown) {
    const errorMessage =
      err instanceof Error ? err.message : 'Invalid access token';
    return c.json({ error: 'Unauthorized', message: errorMessage }, 401);
  }
};
