import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { config } from '@/config';
import { getOrGenerateActiveKey } from '@/lib/keys';
import { authApp } from '@/routes/auth';
import { jwksApp } from '@/routes/jwks';
import { patApp } from '@/routes/pat';
import { rolesApp } from '@/routes/roles';

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
v1.route('/', jwksApp);
v1.route('/', authApp);
v1.route('/', patApp);
v1.route('/', rolesApp);

app.route('/v1', v1);
app.route('/', jwksApp);

app.get('/', (c) =>
  c.json({
    name: 'UNSAReport Identity Provider (IDP)',
    status: 'online',
    issuer: config.idpIssuer,
    endpoints: [
      'GET /v1/auth/google',
      'GET /v1/auth/google/callback',
      'GET /v1/auth/github',
      'GET /v1/auth/github/callback',
      'POST /v1/auth/refresh',
      'POST /v1/auth/logout',
      'GET /v1/auth/me',
      'POST /v1/auth/pat',
      'GET /v1/auth/pat',
      'DELETE /v1/auth/pat/:id',
      'POST /v1/auth/roles',
      'DELETE /v1/auth/roles',
      'GET /v1/auth/roles/me',
      'GET /v1/auth/roles/:subApp',
      'GET /v1/auth/roles/user/:userId',
      'GET /v1/.well-known/jwks.json',
      'POST /v1/auth/keys/rotate',
    ],
  }),
);

app.notFound((c) =>
  c.json({ error: 'Not Found', message: 'Route not found' }, 404),
);

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
