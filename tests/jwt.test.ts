import { describe, expect, test } from 'bun:test';
import { config } from '../src/config.ts';
import { signAccessToken, verifyAccessToken } from '../src/lib/jwt.ts';
import { rotateKeys } from '../src/lib/keys.ts';

describe('JWT Access Token Signing and Verification', () => {
  const dummyUser = {
    sub: '123e4567-e89b-12d3-a456-426614174000',
    email: 'test@unsareport.org',
    name: 'Test Student',
    picture: 'https://example.com/pic.jpg',
  };

  test('signAccessToken generates a valid JWT with correct claims', async () => {
    const token = await signAccessToken(dummyUser);
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3);

    const verified = await verifyAccessToken(token);
    expect(verified.sub).toBe(dummyUser.sub);
    expect(verified.email).toBe(dummyUser.email);
    expect(verified.name).toBe(dummyUser.name);
    expect(verified.picture).toBe(dummyUser.picture);
    expect(verified.iss).toBe(config.idpIssuer);
    expect(verified.type).toBe('access');
    expect(verified.jti).toBeDefined();
    expect(verified.exp).toBeGreaterThan(verified.iat);
  });

  test('verifyAccessToken can verify token signed prior to key rotation', async () => {
    const token = await signAccessToken(dummyUser);

    // Rotate keys
    await rotateKeys();

    // Verification should still succeed because old key exists in DB (even if non-active for new signatures)
    const verified = await verifyAccessToken(token);
    expect(verified.sub).toBe(dummyUser.sub);
  });

  test('verifyAccessToken fails on tampered token', async () => {
    const token = await signAccessToken(dummyUser);
    const parts = token.split('.');
    const tampered = `${parts[0]}.${parts[1]}.tampered_signature`;

    expect(verifyAccessToken(tampered)).rejects.toThrow();
  });
});
