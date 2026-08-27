import { Hono } from 'hono';
import { createPAT, listUserPATs, revokePAT } from '@/lib/tokens';
import { authMiddleware } from '@/middleware/auth';

const patRouter = new Hono();

patRouter.use('*', authMiddleware);

/**
 * Creates a new personal access token for the authenticated user.
 */
patRouter.post('/', async (c) => {
  const user = c.get('user');
  const body = await c.req.json().catch(() => ({}));
  const { name, scopes, expires_at } = body;

  if (!name || typeof name !== 'string') {
    return c.json(
      { error: 'Bad Request', message: 'Field "name" is required' },
      400,
    );
  }

  let expiresAtDate: Date | undefined;
  if (expires_at) {
    expiresAtDate = new Date(expires_at);
    if (Number.isNaN(expiresAtDate.getTime())) {
      return c.json(
        { error: 'Bad Request', message: 'Invalid "expires_at" date format' },
        400,
      );
    }
  }

  const { token, pat } = await createPAT(
    user.id,
    name,
    Array.isArray(scopes) ? scopes : [],
    expiresAtDate,
  );

  return c.json(
    {
      token,
      pat: {
        id: pat.id,
        name: pat.name,
        scopes: pat.scopes,
        createdAt: pat.createdAt,
        expiresAt: pat.expiresAt,
      },
    },
    201,
  );
});

/**
 * Lists all active personal access tokens for the authenticated user.
 */
patRouter.get('/', async (c) => {
  const user = c.get('user');
  const pats = await listUserPATs(user.id);
  return c.json({ pats });
});

/**
 * Revokes a personal access token by ID for the authenticated user.
 */
patRouter.delete('/:id', async (c) => {
  const user = c.get('user');
  const patId = c.req.param('id');

  const success = await revokePAT(user.id, patId);
  if (!success) {
    return c.json(
      { error: 'Not Found', message: 'PAT not found or already revoked' },
      404,
    );
  }

  return c.json({ success: true, message: 'PAT revoked successfully' });
});

export { patRouter };
