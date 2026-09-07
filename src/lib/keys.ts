import { desc, eq } from 'drizzle-orm';
import {
  exportJWK,
  exportPKCS8,
  exportSPKI,
  generateKeyPair,
  importSPKI,
  type JWK,
} from 'jose';
import { db } from '@/db/index';
import { signingKeys } from '@/db/schema';
import { generateRandomHex } from '@/lib/hash';

/**
 * Represents the generated RSA key pair details including key ID and PEM strings.
 */
export interface KeyPairResult {
  kid: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

/**
 * Generates a new RS256 RSA key pair in PEM format with a unique key ID.
 *
 * @returns A promise resolving to an object containing the key ID, public key PEM, and private key PEM.
 */
export async function generateRSAKeyPair(): Promise<KeyPairResult> {
  const { publicKey, privateKey } = await generateKeyPair('RS256', {
    extractable: true,
  });
  const publicKeyPem = await exportSPKI(publicKey);
  const privateKeyPem = await exportPKCS8(privateKey);
  const kid = `key_${generateRandomHex(8)}`;
  return { kid, publicKeyPem, privateKeyPem };
}

/**
 * Fetches the currently active RSA signing key from the database, or generates and stores a new one if none exists.
 *
 * @returns A promise resolving to the active signing key database record.
 */
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

/**
 * Deactivates all existing active signing keys and generates a new active RSA key pair.
 *
 * @returns A promise resolving to the newly created active signing key record.
 */
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

/**
 * Retrieves all active public signing keys formatted as JSON Web Keys (JWK) for JWKS export.
 *
 * @returns A promise resolving to an array of active public keys formatted as JWK objects.
 */
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
