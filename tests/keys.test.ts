import { describe, expect, test } from 'bun:test';
import {
  generateRSAKeyPair,
  getAllActivePublicKeys,
  getOrGenerateActiveKey,
  rotateKeys,
} from '../src/lib/keys.ts';

describe('RSA Key Management', () => {
  test('generateRSAKeyPair creates valid RSA 2048 key pair in PEM format', async () => {
    const keyPair = await generateRSAKeyPair();
    expect(keyPair.kid).toBeDefined();
    expect(keyPair.kid.startsWith('key_')).toBe(true);
    expect(keyPair.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(keyPair.privateKeyPem).toContain('-----BEGIN PRIVATE KEY-----');
  });

  test('getOrGenerateActiveKey returns or creates active key', async () => {
    const activeKey = await getOrGenerateActiveKey();
    expect(activeKey).toBeDefined();
    expect(activeKey.active).toBe(true);
    expect(activeKey.kid).toBeDefined();
  });

  test('getAllActivePublicKeys returns JWKS key structures', async () => {
    const jwks = await getAllActivePublicKeys();
    expect(Array.isArray(jwks)).toBe(true);
    expect(jwks.length).toBeGreaterThan(0);

    const [firstKey] = jwks;
    expect(firstKey.kty).toBe('RSA');
    expect(firstKey.use).toBe('sig');
    expect(firstKey.alg).toBe('RS256');
    expect(firstKey.kid).toBeDefined();
    expect(firstKey.n).toBeDefined();
    expect(firstKey.e).toBeDefined();
  });

  test('rotateKeys deactivates old active key and creates a new active key', async () => {
    const oldKey = await getOrGenerateActiveKey();
    const newKey = await rotateKeys();

    expect(newKey.kid).not.toBe(oldKey.kid);
    expect(newKey.active).toBe(true);

    const activeKeys = await getAllActivePublicKeys();
    expect(activeKeys.some((k) => k.kid === newKey.kid)).toBe(true);
    expect(activeKeys.some((k) => k.kid === oldKey.kid)).toBe(false);
  });
});
