import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { config } from '@/config';
import {
  oauthAccounts,
  personalAccessTokens,
  refreshTokens,
  signingKeys,
  users,
} from '@/db/schema';

const schema = {
  users,
  oauthAccounts,
  refreshTokens,
  personalAccessTokens,
  signingKeys,
};

const queryClient = postgres(config.databaseUrl);
export const db = drizzle(queryClient, { schema });
export { queryClient };
