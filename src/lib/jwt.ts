import { eq } from 'drizzle-orm';
import {
  decodeProtectedHeader,
  importPKCS8,
  importSPKI,
  jwtVerify,
  SignJWT,
} from 'jose';
import { config } from '../config.ts';
import { db } from '../db/index.ts';
import { signingKeys, userRoles } from '../db/schema.ts';
import type { AccessTokenClaims, Role, UserPayload } from '../types.ts';
import { getOrGenerateActiveKey } from './keys.ts';

export async function getUserRoles(
  userId: string,
): Promise<Record<string, Role>> {
  const rows = await db
    .select({ subApp: userRoles.subApp, role: userRoles.role })
    .from(userRoles)
    .where(eq(userRoles.userId, userId));

  return Object.fromEntries(rows.map((r) => [r.subApp, r.role as Role]));
}

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
