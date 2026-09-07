import { and, eq, gt, isNull } from 'drizzle-orm';
import { config } from '@/config';
import { db } from '@/db/index';
import { personalAccessTokens, refreshTokens, users } from '@/db/schema';
import { generateRandomHex, hashToken } from '@/lib/hash';

/**
 * Generates and stores a new refresh token for a user.
 *
 * @param userId - The ID of the user.
 * @returns A promise resolving to the generated plaintext refresh token string.
 */
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

/**
 * Verifies a refresh token, revokes it, and issues a new refresh token (token rotation).
 *
 * @param token - The plaintext refresh token to verify and rotate.
 * @returns A promise resolving to an object containing the associated user ID and new refresh token.
 * @throws Error if the token is invalid, expired, or revoked.
 */
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

  await db
    .update(refreshTokens)
    .set({ revokedAt: now })
    .where(eq(refreshTokens.id, record.id));

  const newRefreshToken = await createRefreshToken(record.userId);

  return { userId: record.userId, newRefreshToken };
}

/**
 * Revokes an existing refresh token.
 *
 * @param token - The plaintext refresh token to revoke.
 * @returns A promise resolving to true if the token was revoked, false otherwise.
 */
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

/**
 * Creates a new personal access token (PAT) for a user.
 *
 * @param userId - The ID of the user creating the PAT.
 * @param name - A descriptive name for the PAT.
 * @param scopes - Optional list of permission scopes.
 * @param expiresAt - Optional expiration date.
 * @returns A promise resolving to the generated plaintext token and created database record.
 */
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

/**
 * Verifies a personal access token (PAT) and updates its last used timestamp.
 *
 * @param token - The raw PAT string to verify.
 * @returns A promise resolving to an object with the PAT record and user, or null if invalid or expired.
 */
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

/**
 * Lists all active (non-revoked) personal access tokens for a user.
 *
 * @param userId - The ID of the user whose PATs are listed.
 * @returns A promise resolving to an array of active PAT records.
 */
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

/**
 * Revokes a user's personal access token by ID.
 *
 * @param userId - The ID of the owning user.
 * @param patId - The ID of the PAT to revoke.
 * @returns A promise resolving to true if the PAT was successfully revoked, false otherwise.
 */
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
