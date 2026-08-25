import { and, eq, gt, isNull } from 'drizzle-orm';
import { config } from '../config.ts';
import { db } from '../db/index.ts';
import { personalAccessTokens, refreshTokens, users } from '../db/schema.ts';
import { generateRandomHex, hashToken } from './hash.ts';

export async function createRefreshToken(userId: string): Promise<string> {
  const token = `unsareport_rf_${generateRandomHex(32)}`;
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + config.refreshTokenTtl * 1000);

  await db.insert(refreshTokens).values({
    userId,
    tokenHash,
    expiresAt,
  });

  return token;
}

export async function verifyAndRotateRefreshToken(
  token: string,
): Promise<{ userId: string; newRefreshToken: string }> {
  const tokenHash = hashToken(token);
  const now = new Date();

  const [record] = await db
    .select()
    .from(refreshTokens)
    .where(
      and(
        eq(refreshTokens.tokenHash, tokenHash),
        isNull(refreshTokens.revokedAt),
        gt(refreshTokens.expiresAt, now),
      ),
    );

  if (!record) {
    throw new Error('Invalid or expired refresh token');
  }

  // Revoke old refresh token (refresh token rotation)
  await db
    .update(refreshTokens)
    .set({ revokedAt: now })
    .where(eq(refreshTokens.id, record.id));

  // Issue new refresh token
  const newRefreshToken = await createRefreshToken(record.userId);

  return { userId: record.userId, newRefreshToken };
}

export async function revokeRefreshToken(token: string): Promise<boolean> {
  const tokenHash = hashToken(token);
  const res = await db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(refreshTokens.tokenHash, tokenHash),
        isNull(refreshTokens.revokedAt),
      ),
    )
    .returning();

  return res.length > 0;
}

export async function createPAT(
  userId: string,
  name: string,
  scopes?: string[],
  expiresAt?: Date | null,
) {
  const token = `unsareport_pat_${generateRandomHex(32)}`;
  const tokenHash = hashToken(token);

  const [pat] = await db
    .insert(personalAccessTokens)
    .values({
      userId,
      name,
      tokenHash,
      scopes: scopes || [],
      expiresAt: expiresAt || null,
    })
    .returning();

  return { token, pat };
}

export async function verifyPAT(token: string) {
  if (!token.startsWith('unsareport_pat_')) {
    return null;
  }
  const tokenHash = hashToken(token);
  const now = new Date();

  const [pat] = await db
    .select()
    .from(personalAccessTokens)
    .where(
      and(
        eq(personalAccessTokens.tokenHash, tokenHash),
        isNull(personalAccessTokens.revokedAt),
      ),
    );

  if (!pat) {
    return null;
  }

  if (pat.expiresAt && pat.expiresAt < now) {
    return null;
  }

  // Update last_used_at asynchronously
  await db
    .update(personalAccessTokens)
    .set({ lastUsedAt: now })
    .where(eq(personalAccessTokens.id, pat.id));

  const [user] = await db.select().from(users).where(eq(users.id, pat.userId));

  if (!user) {
    return null;
  }

  return { pat, user };
}

export async function listUserPATs(userId: string) {
  return await db
    .select({
      id: personalAccessTokens.id,
      name: personalAccessTokens.name,
      scopes: personalAccessTokens.scopes,
      lastUsedAt: personalAccessTokens.lastUsedAt,
      expiresAt: personalAccessTokens.expiresAt,
      createdAt: personalAccessTokens.createdAt,
      revokedAt: personalAccessTokens.revokedAt,
    })
    .from(personalAccessTokens)
    .where(
      and(
        eq(personalAccessTokens.userId, userId),
        isNull(personalAccessTokens.revokedAt),
      ),
    );
}

export async function revokePAT(
  userId: string,
  patId: string,
): Promise<boolean> {
  const res = await db
    .update(personalAccessTokens)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(personalAccessTokens.id, patId),
        eq(personalAccessTokens.userId, userId),
        isNull(personalAccessTokens.revokedAt),
      ),
    )
    .returning();

  return res.length > 0;
}
