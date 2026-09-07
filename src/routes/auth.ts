import process from 'node:process';
import { eq } from 'drizzle-orm';
import type { Context } from 'hono';
import { Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { config } from '@/config';
import { db } from '@/db/index';
import { users } from '@/db/schema';
import { generateRandomHex } from '@/lib/hash';
import { getUserRoles, signAccessToken } from '@/lib/jwt';
import { providerRegistry, upsertOAuthUser } from '@/lib/oauth';
import {
  createRefreshToken,
  revokeRefreshToken,
  verifyAndRotateRefreshToken,
} from '@/lib/tokens';
import { authMiddleware } from '@/middleware/auth';

const authRouter = new Hono();

/**
 * Initiates the OAuth redirect flow for a specified provider.
 *
 * @param c - Hono context object.
 * @param providerName - Name of the OAuth provider.
 * @returns A HTTP redirect response to the OAuth provider authorization endpoint.
 */
function handleOAuthRedirect(c: Context, providerName: string) {
  const provider = providerRegistry.get(providerName);
  if (!provider) {
    return c.json(
      {
        error: 'Bad Request',
        message: `Unsupported OAuth provider: ${providerName}`,
      },
      400,
    );
  }

  const state = `st_${generateRandomHex(16)}`;
  setCookie(c, `oauth_state_${providerName}`, state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax',
    maxAge: 600,
    path: '/',
  });

  const authUrl = provider.getAuthUrl(state);
  return c.redirect(authUrl);
}

/**
 * Handles the OAuth callback from an external authentication provider.
 *
 * @param c - Hono context object.
 * @param providerName - Name of the OAuth provider handling the callback.
 * @returns A promise resolving to a redirect response to the client application or an error JSON response.
 */
async function handleOAuthCallback(c: Context, providerName: string) {
  const provider = providerRegistry.get(providerName);
  if (!provider) {
    return c.json(
      {
        error: 'Bad Request',
        message: `Unsupported OAuth provider: ${providerName}`,
      },
      400,
    );
  }

  const code = c.req.query('code');
  const state = c.req.query('state');
  const savedState = getCookie(c, `oauth_state_${providerName}`);

  deleteCookie(c, `oauth_state_${providerName}`, { path: '/' });

  if (!code) {
    return c.json(
      { error: 'Bad Request', message: 'Missing authorization code' },
      400,
    );
  }

  if (savedState && state !== savedState) {
    return c.json(
      { error: 'Bad Request', message: 'Invalid OAuth state parameter' },
      400,
    );
  }

  try {
    const oauthUserInfo = await provider.exchangeCode(code);
    const user = await upsertOAuthUser(providerName, oauthUserInfo);
    const roles = await getUserRoles(user.id);

    const accessToken = await signAccessToken({
      sub: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture,
      roles,
    });

    const refreshToken = await createRefreshToken(user.id);

    setCookie(c, 'refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Lax',
      maxAge: config.refreshTokenTtl,
      path: '/',
    });

    const redirectUrl = new URL(config.clientRedirectUrl);
    redirectUrl.hash = `access_token=${accessToken}&token_type=Bearer&expires_in=${config.accessTokenTtl}`;

    return c.redirect(redirectUrl.toString());
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : 'Authentication failed';
    return c.json({ error: 'Authentication Failed', message }, 500);
  }
}

/**
 * Route handler for GET /google
 * Initiates the Google OAuth authorization flow.
 */
authRouter.get('/google', (c) => handleOAuthRedirect(c, 'google'));

/**
 * Route handler for GET /google/callback
 * Handles Google OAuth callback and exchanges code for tokens.
 */
authRouter.get('/google/callback', (c) => handleOAuthCallback(c, 'google'));

/**
 * Route handler for GET /github
 * Initiates the GitHub OAuth authorization flow.
 */
authRouter.get('/github', (c) => handleOAuthRedirect(c, 'github'));

/**
 * Route handler for GET /github/callback
 * Handles GitHub OAuth callback and exchanges code for tokens.
 */
authRouter.get('/github/callback', (c) => handleOAuthCallback(c, 'github'));

/**
 * Route handler for POST /refresh
 * Exchanges a valid refresh token for a new JWT access token and rotated refresh token.
 */
authRouter.post('/refresh', async (c) => {
  const body = await c.req
    .json<{ refresh_token?: string }>()
    .catch(() => ({}) as { refresh_token?: string });
  const refreshTokenInput = body.refresh_token || getCookie(c, 'refresh_token');

  if (!refreshTokenInput) {
    return c.json(
      { error: 'Bad Request', message: 'Refresh token is required' },
      400,
    );
  }

  try {
    const { userId, newRefreshToken } =
      await verifyAndRotateRefreshToken(refreshTokenInput);
    const [user] = await db.select().from(users).where(eq(users.id, userId));

    if (!user) {
      return c.json({ error: 'Unauthorized', message: 'User not found' }, 401);
    }

    const roles = await getUserRoles(user.id);
    const accessToken = await signAccessToken({
      sub: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture,
      roles,
    });

    setCookie(c, 'refresh_token', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Lax',
      maxAge: config.refreshTokenTtl,
      path: '/',
    });

    return c.json({
      access_token: accessToken,
      refresh_token: newRefreshToken,
      token_type: 'Bearer',
      expires_in: config.accessTokenTtl,
    });
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : 'Invalid refresh token';
    return c.json(
      {
        error: 'Unauthorized',
        message,
      },
      401,
    );
  }
});

/**
 * Route handler for POST /logout
 * Revokes the active refresh token and clears auth cookies.
 */
authRouter.post('/logout', async (c) => {
  const body = await c.req
    .json<{ refresh_token?: string }>()
    .catch(() => ({}) as { refresh_token?: string });
  const refreshTokenInput = body.refresh_token || getCookie(c, 'refresh_token');

  if (refreshTokenInput) {
    await revokeRefreshToken(refreshTokenInput);
  }

  deleteCookie(c, 'refresh_token', { path: '/' });

  return c.json({ success: true, message: 'Logged out successfully' });
});

/**
 * Route handler for GET /me
 * Returns user details, authentication type, and roles for the authenticated user.
 */
authRouter.get('/me', authMiddleware, (c) => {
  const user = c.get('user');
  const authType = c.get('authType');
  const jwtClaims = c.get('jwtClaims');
  const pat = c.get('pat');
  const roles = c.get('roles');

  return c.json({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    },
    auth_type: authType,
    roles,
    ...(authType === 'jwt' ? { jwt_claims: jwtClaims } : {}),
    ...(authType === 'pat' && pat
      ? { pat_info: { id: pat.id, name: pat.name, scopes: pat.scopes } }
      : {}),
  });
});

export { authRouter };
