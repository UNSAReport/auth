import { createHash, randomBytes } from 'node:crypto';

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function generateRandomHex(byteCount = 32): string {
  return randomBytes(byteCount).toString('hex');
}
