import { desc, eq } from 'drizzle-orm';
import {
  exportJWK,
  exportPKCS8,
  exportSPKI,
  generateKeyPair,
  importSPKI,
  type JWK,
} from 'jose';
import { db } from '../db/index.ts';
import { signingKeys } from '../db/schema.ts';
import { generateRandomHex } from './hash.ts';

export interface KeyPairResult {
  kid: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

export async function generateRSAKeyPair(): Promise<KeyPairResult> {
  const { publicKey, privateKey } = await generateKeyPair('RS256', {
    extractable: true,
  });
  const publicKeyPem = await exportSPKI(publicKey);
  const privateKeyPem = await exportPKCS8(privateKey);
  const kid = `key_${generateRandomHex(8)}`;
  return { kid, publicKeyPem, privateKeyPem };
}

export async function getOrGenerateActiveKey() {
  const activeKeys = await db
    .select()
    .from(signingKeys)
    .where(eq(signingKeys.active, true))
    .orderBy(desc(signingKeys.createdAt));

  if (activeKeys.length > 0) {
    return activeKeys[0];
  }

  const { kid, publicKeyPem, privateKeyPem } = await generateRSAKeyPair();
  const [insertedKey] = await db
    .insert(signingKeys)
    .values({
      kid,
      publicKey: publicKeyPem,
      privateKey: privateKeyPem,
      algorithm: 'RS256',
      active: true,
    })
    .returning();

  return insertedKey;
}

export async function rotateKeys() {
  const { kid, publicKeyPem, privateKeyPem } = await generateRSAKeyPair();
  const now = new Date();

  await db
    .update(signingKeys)
    .set({ rotatedAt: now, active: false })
    .where(eq(signingKeys.active, true));

  const [newKey] = await db
    .insert(signingKeys)
    .values({
      kid,
      publicKey: publicKeyPem,
      privateKey: privateKeyPem,
      algorithm: 'RS256',
      active: true,
    })
    .returning();

  return newKey;
}

export async function getAllActivePublicKeys(): Promise<JWK[]> {
  const keys = await db
    .select()
    .from(signingKeys)
    .where(eq(signingKeys.active, true));

  return await Promise.all(
    keys.map(async (k) => {
      const keyLike = await importSPKI(k.publicKey, k.algorithm || 'RS256');
      const jwk = await exportJWK(keyLike);
      return {
        ...jwk,
        kid: k.kid,
        use: 'sig',
        alg: k.algorithm || 'RS256',
      };
    }),
  );
}
