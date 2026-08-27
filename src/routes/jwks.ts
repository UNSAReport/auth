import { Hono } from 'hono';
import { getAllActivePublicKeys } from '@/lib/keys';

const jwksRouter = new Hono();
/**
 * Serves active public RSA keys as a JSON Web Key Set (JWKS).
 */
jwksRouter.get('/.well-known/jwks.json', async (c) => {
  const keys = await getAllActivePublicKeys();
  return c.json({ keys }, 200, {
    'Cache-Control': 'public, max-age=3600',
  });
});

export { jwksRouter };
