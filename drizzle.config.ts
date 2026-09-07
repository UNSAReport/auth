import process from 'node:process';
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './src/db/migrations',
  dialect: 'postgresql',
  dbCredentials: {
    url:
      process.env.DATABASE_URL ||
      'postgresql://idp:idppassword@localhost:5432/idp_db',
  },
});
