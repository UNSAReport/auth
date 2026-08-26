import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { config } from '@/config';
import { getOrGenerateActiveKey } from '@/lib/keys';
import { authApp } from '@/routes/auth';
import { jwksApp } from '@/routes/jwks';
import { patApp } from '@/routes/pat';
import { rolesApp } from '@/routes/roles';

const app = new Hono();

// Enable CORS for allowed sub-app origins
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

// Ensure active RSA key exists on startup
getOrGenerateActiveKey().catch((err) => {
  console.error('Failed to initialize active signing key:', err);
});

// Mount Routes
app.route('/', jwksApp);
app.route('/', authApp);
app.route('/', patApp);
app.route('/', rolesApp);

// Health check / root endpoint
app.get('/', (c) =>
  c.json({
    name: 'UNSAReport Identity Provider (IDP)',
    status: 'online',
    issuer: config.idpIssuer,
    endpoints: [
      'GET /auth/google',
      'GET /auth/google/callback',
      'GET /auth/github',
      'GET /auth/github/callback',
      'POST /auth/refresh',
      'POST /auth/logout',
      'GET /auth/me',
      'POST /auth/pat',
      'GET /auth/pat',
      'DELETE /auth/pat/:id',
      'POST /auth/roles',
      'DELETE /auth/roles',
      'GET /auth/roles/me',
      'GET /auth/roles/:subApp',
      'GET /auth/roles/user/:userId',
      'GET /.well-known/jwks.json',
      'POST /auth/keys/rotate',
    ],
  }),
);

// Global 404 Handler
app.notFound((c) =>
  c.json({ error: 'Not Found', message: 'Route not found' }, 404),
);

// Global Error Handler
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
