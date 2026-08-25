import { Hono } from 'hono';
import { config } from '../config.ts';
import { getAllActivePublicKeys, rotateKeys } from '../lib/keys.ts';

const jwksApp = new Hono();

// Public JWKS Endpoint
jwksApp.get('/.well-known/jwks.json', async (c) => {
  const keys = await getAllActivePublicKeys();
  return c.json({ keys }, 200, {
    'Cache-Control': 'public, max-age=3600',
  });
});

// Key Rotation Endpoint (Admin only)
jwksApp.post('/auth/keys/rotate', async (c) => {
  const authHeader = c.req.header('Authorization');
  const adminHeader = c.req.header('X-Admin-Key');

  let keyInput = adminHeader;
  if (!keyInput && authHeader && authHeader.startsWith('Bearer ')) {
    keyInput = authHeader.substring(7);
  }

  if (keyInput !== config.adminApiKey) {
    return c.json(
      { error: 'Unauthorized', message: 'Invalid admin API key' },
      401,
    );
  }

  const newKey = await rotateKeys();
  return c.json({
    success: true,
    message: 'Key rotated successfully',
    key: {
      kid: newKey.kid,
      algorithm: newKey.algorithm,
      createdAt: newKey.createdAt,
    },
  });
});

export { jwksApp };
