import { describe, expect, test } from 'bun:test';
import { db } from '../src/db/index.ts';
import { users } from '../src/db/schema.ts';
import {
  createPAT,
  createRefreshToken,
  listUserPATs,
  revokePAT,
  revokeRefreshToken,
  verifyAndRotateRefreshToken,
  verifyPAT,
} from '../src/lib/tokens.ts';

describe('Refresh Token & PAT Lifecycle', () => {
  let testUserId: string;

  test('setup test user', async () => {
    const [u] = await db
      .insert(users)
      .values({
        email: `token_test_${Date.now()}@unsareport.org`,
        name: 'Token Tester',
      })
      .returning();
    testUserId = u.id;
    expect(testUserId).toBeDefined();
  });

  describe('Refresh Token', () => {
    test('create, rotate, and revoke refresh token', async () => {
      const rfToken = await createRefreshToken(testUserId);
      expect(rfToken.startsWith('unsareport_rf_')).toBe(true);

      // Rotate token
      const rotated = await verifyAndRotateRefreshToken(rfToken);
      expect(rotated.userId).toBe(testUserId);
      expect(rotated.newRefreshToken).toBeDefined();
      expect(rotated.newRefreshToken).not.toBe(rfToken);

      // Attempting to reuse old refresh token should fail
      expect(verifyAndRotateRefreshToken(rfToken)).rejects.toThrow(
        'Invalid or expired refresh token',
      );

      // Revoke rotated token
      const revoked = await revokeRefreshToken(rotated.newRefreshToken);
      expect(revoked).toBe(true);

      // Attempting to reuse revoked refresh token should fail
      expect(
        verifyAndRotateRefreshToken(rotated.newRefreshToken),
      ).rejects.toThrow();
    });
  });

  describe('Personal Access Token (PAT)', () => {
    test('create, verify, update last_used_at, list, and revoke PAT', async () => {
      const scopes = ['registry', 'slides'];
      const { token, pat } = await createPAT(testUserId, 'Laptop CLI', scopes);

      expect(token.startsWith('unsareport_pat_')).toBe(true);
      expect(pat.name).toBe('Laptop CLI');
      expect(pat.scopes).toEqual(scopes);

      // Verify PAT
      const verified = await verifyPAT(token);
      expect(verified).not.toBeNull();
      expect(verified?.user.id).toBe(testUserId);
      expect(verified?.pat.name).toBe('Laptop CLI');
      expect(verified?.pat.lastUsedAt).toBeDefined();

      // List PATs
      const pats = await listUserPATs(testUserId);
      expect(pats.length).toBeGreaterThan(0);
      expect(pats.some((p) => p.id === pat.id)).toBe(true);

      // Revoke PAT
      const revoked = await revokePAT(testUserId, pat.id);
      expect(revoked).toBe(true);

      // Verifying revoked PAT should fail
      const verifiedAfterRevoke = await verifyPAT(token);
      expect(verifiedAfterRevoke).toBeNull();
    });
  });
});
