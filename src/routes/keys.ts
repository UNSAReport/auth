import { Hono } from 'hono';
import { config } from '@/config';
import { rotateKeys } from '@/lib/keys';

const keysRouter = new Hono();

/**
 * Rotates active RSA signing keys when presented with a valid admin key.
 */
keysRouter.post('/rotate', async (c) => {
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

export { keysRouter };
