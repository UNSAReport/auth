import process from 'node:process';
export const config = {
  databaseUrl:
    process.env.DATABASE_URL ||
    'postgresql://idp:idppassword@localhost:5432/idp_db',

  googleClientId: process.env.GOOGLE_CLIENT_ID || '',
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET || '',

  githubClientId: process.env.GITHUB_CLIENT_ID || '',
  githubClientSecret: process.env.GITHUB_CLIENT_SECRET || '',

  idpIssuer: process.env.IDP_ISSUER || 'https://auth.unsareport.org',
  idpPort: Number.parseInt(process.env.IDP_PORT || '3000', 10),
  idpAllowedOrigins: (
    process.env.IDP_ALLOWED_ORIGINS ||
    'http://localhost:5173,https://slides.unsareport.org'
  )
    .split(',')
    .map((o) => o.trim()),

  accessTokenTtl: Number.parseInt(process.env.ACCESS_TOKEN_TTL || '900', 10),
  refreshTokenTtl: Number.parseInt(
    process.env.REFRESH_TOKEN_TTL || '2592000',
    10,
  ),

  clientRedirectUrl: process.env.CLIENT_REDIRECT_URL || 'http://localhost:5173',
  adminApiKey: process.env.ADMIN_API_KEY || 'admin-secret-key-12345',
};
