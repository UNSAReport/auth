import process from 'node:process';
import { eq } from 'drizzle-orm';
import type { Context } from 'hono';
import { Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { config } from '../config.ts';
import { db } from '../db/index.ts';
import { users } from '../db/schema.ts';
import { generateRandomHex } from '../lib/hash.ts';
import { signAccessToken } from '../lib/jwt.ts';
import { providerRegistry, upsertOAuthUser } from '../lib/oauth.ts';
import {
  createRefreshToken,
  revokeRefreshToken,
  verifyAndRotateRefreshToken,
} from '../lib/tokens.ts';
import { authMiddleware } from '../middleware/auth.ts';

const authApp = new Hono();

// Helper to handle provider redirect
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
    maxAge: 600, // 10 minutes
    path: '/',
  });

  const authUrl = provider.getAuthUrl(state);
  return c.redirect(authUrl);
}

// Helper to handle provider callback
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

    const accessToken = await signAccessToken({
      sub: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture,
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

// GET /auth/google
authApp.get('/auth/google', (c) => handleOAuthRedirect(c, 'google'));

// GET /auth/google/callback
authApp.get('/auth/google/callback', (c) => handleOAuthCallback(c, 'google'));

// GET /auth/github (Phase 4)
authApp.get('/auth/github', (c) => handleOAuthRedirect(c, 'github'));

// GET /auth/github/callback (Phase 4)
authApp.get('/auth/github/callback', (c) => handleOAuthCallback(c, 'github'));

// POST /auth/refresh
authApp.post('/auth/refresh', async (c) => {
  const body = await c.req.json<{ refresh_token?: string }>().catch(() => ({}));
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

    const accessToken = await signAccessToken({
      sub: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture,
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

// POST /auth/logout
authApp.post('/auth/logout', async (c) => {
  const body = await c.req.json<{ refresh_token?: string }>().catch(() => ({}));
  const refreshTokenInput = body.refresh_token || getCookie(c, 'refresh_token');

  if (refreshTokenInput) {
    await revokeRefreshToken(refreshTokenInput);
  }

  deleteCookie(c, 'refresh_token', { path: '/' });

  return c.json({ success: true, message: 'Logged out successfully' });
});

// GET /auth/me
authApp.get('/auth/me', authMiddleware, (c) => {
  const user = c.get('user');
  const authType = c.get('authType');
  const jwtClaims = c.get('jwtClaims');
  const pat = c.get('pat');

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
    ...(authType === 'jwt' ? { jwt_claims: jwtClaims } : {}),
    ...(authType === 'pat' && pat
      ? { pat_info: { id: pat.id, name: pat.name, scopes: pat.scopes } }
      : {}),
  });
});

export { authApp };
