import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { config } from '@/config';
import { getOrGenerateActiveKey } from '@/lib/keys';
import { authRouter } from '@/routes/auth';
import { jwksRouter } from '@/routes/jwks';
import { keysRouter } from '@/routes/keys';
import { patRouter } from '@/routes/pat';
import { rolesRouter } from '@/routes/roles';

const app = new Hono();

app.use(
  '*',
  cors({
    origin: (origin) => {
      if (!origin) {
        return '*';
      }
      if (
        config.idpAllowedOrigins.includes(origin) ||
        config.idpAllowedOrigins.includes('*')
      ) {
        return origin;
      }
      return config.idpAllowedOrigins[0] || '*';
    },
    allowHeaders: ['Content-Type', 'Authorization', 'X-Admin-Key'],
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
  }),
);

getOrGenerateActiveKey().catch((err) => {
  console.error('Failed to initialize active signing key:', err);
});

const v1 = new Hono();
v1.route('/auth', authRouter);
v1.route('/auth/pat', patRouter);
v1.route('/auth/roles', rolesRouter);
v1.route('/auth/keys', keysRouter);

app.route('/v1', v1);
app.route('/', jwksRouter);

/**
 * Route handler for GET /
 * Returns status metadata and available API endpoints.
 */
app.get('/', (c) =>
  c.json({
    name: 'UNSAReport Identity Provider (IDP)',
    status: 'online',
    issuer: config.idpIssuer,
    endpoints: app.routes
      .filter((r) => r.path !== '/' && r.method !== 'ALL')
      .map((r) => `${r.method} ${r.path}`),
  }),
);

/**
 * Not-found handler for unmatched routes.
 */
app.notFound((c) =>
  c.json({ error: 'Not Found', message: 'Route not found' }, 404),
);

/**
 * Global error handler for unhandled application errors.
 */
app.onError((err, c) =>
  c.json(
    {
      error: 'Internal Server Error',
      message: err.message || 'An unexpected error occurred',
    },
    500,
  ),
);

export default {
  port: config.idpPort,
  fetch: app.fetch,
};
