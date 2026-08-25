import { describe, expect, test } from 'bun:test';
import { generateRandomHex, hashToken } from '../src/lib/hash.ts';

describe('Hash Utilities', () => {
  test('generateRandomHex creates hex strings of correct length', () => {
    const hex16 = generateRandomHex(16);
    expect(hex16).toHaveLength(32); // 16 bytes = 32 hex chars

    const hex32 = generateRandomHex(32);
    expect(hex32).toHaveLength(64); // 32 bytes = 64 hex chars
  });

  test('hashToken computes deterministic SHA-256 hash', () => {
    const input = 'unsareport_pat_test12345';
    const hash1 = hashToken(input);
    const hash2 = hashToken(input);

    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
    expect(hash1).not.toBe(input);
  });
});
