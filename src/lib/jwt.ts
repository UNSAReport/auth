import { eq } from 'drizzle-orm';
import {
  decodeProtectedHeader,
  importPKCS8,
  importSPKI,
  jwtVerify,
  SignJWT,
} from 'jose';
import { config } from '@/config';
import { db } from '@/db/index';
import { signingKeys, userRoles } from '@/db/schema';
import { getOrGenerateActiveKey } from '@/lib/keys';
import type { AccessTokenClaims, Role, UserPayload } from '@/types';

/**
 * Retrieves all assigned application roles for a given user ID.
 *
 * @param userId - The ID of the user whose roles are being fetched.
 * @returns A promise resolving to a mapping of sub-app identifiers to assigned roles.
 */
export async function getUserRoles(
  userId: string,
): Promise<Record<string, Role>> {
  const rows = await db
    .select({ subApp: userRoles.subApp, role: userRoles.role })
    .from(userRoles)
    .where(eq(userRoles.userId, userId));

  return Object.fromEntries(rows.map((r) => [r.subApp, r.role as Role]));
}

/**
 * Signs and creates a JWT access token for a user using the active RSA private key.
 *
 * @param user - The user payload containing identity and role claims.
 * @returns A promise resolving to the signed JWT access token string.
 */
export async function signAccessToken(user: UserPayload): Promise<string> {
  const activeKey = await getOrGenerateActiveKey();
  const privateKey = await importPKCS8(
    activeKey.privateKey,
    activeKey.algorithm || 'RS256',
  );

  const jti = `jti_${crypto.randomUUID()}`;

  const jwt = await new SignJWT({
    sub: user.sub,
    email: user.email,
    name: user.name,
    picture: user.picture || null,
    roles: user.roles || {},
    type: 'access',
  })
    .setProtectedHeader({
      alg: activeKey.algorithm || 'RS256',
      kid: activeKey.kid,
      typ: 'JWT',
    })
    .setIssuer(config.idpIssuer)
    .setIssuedAt()
    .setExpirationTime(`${config.accessTokenTtl}s`)
    .setJti(jti)
    .sign(privateKey);

  return jwt;
}

/**
 * Verifies an access token signature and validates its claims against active public keys.
 *
 * @param token - The JWT access token string to verify.
 * @returns A promise resolving to the verified access token claims.
 * @throws Error if the token header is missing kid, key is unknown, or token is invalid.
 */
export async function verifyAccessToken(
  token: string,
): Promise<AccessTokenClaims> {
  const unverifiedHeader = decodeProtectedHeader(token);
  const { kid } = unverifiedHeader;

  if (!kid) {
    throw new Error('Missing kid in token header');
  }

  const [keyRecord] = await db
    .select()
    .from(signingKeys)
    .where(eq(signingKeys.kid, kid));

  if (!keyRecord) {
    throw new Error(`Unknown signing key ID: ${kid}`);
  }

  const publicKey = await importSPKI(
    keyRecord.publicKey,
    keyRecord.algorithm || 'RS256',
  );
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: config.idpIssuer,
  });

  if (payload.type !== 'access') {
    throw new Error('Invalid token type claim');
  }

  return payload as unknown as AccessTokenClaims;
}
