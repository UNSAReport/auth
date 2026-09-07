import { createHash, randomBytes } from 'node:crypto';

/**
 * Hashes a plaintext token string using the SHA-256 algorithm.
 *
 * @param token - The plaintext token string to hash.
 * @returns The hex-encoded SHA-256 hash.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Generates a cryptographically secure random hexadecimal string.
 *
 * @param byteCount - The number of random bytes to generate (defaults to 32).
 * @returns The generated hexadecimal string.
 */
export function generateRandomHex(byteCount = 32): string {
  return randomBytes(byteCount).toString('hex');
}
