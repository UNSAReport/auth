export type Role = 'user' | 'admin';

/**
 * Represents the payload data for an authenticated user.
 */
export interface UserPayload {
  sub: string;
  email: string;
  name: string;
  picture?: string | null;
  roles?: Record<string, Role>;
}

/**
 * Represents the decoded JWT claims for an access token.
 */
export interface AccessTokenClaims extends UserPayload {
  roles: Record<string, Role>;
  iss: string;
  iat: number;
  exp: number;
  jti: string;
  type: 'access';
}

/**
 * Represents an authenticated user entity.
 */
export interface AuthUser {
  id: string;
  email: string;
  name: string;
  picture: string | null;
  createdAt: Date | null;
  updatedAt: Date | null;
}

/**
 * Represents standard user profile metadata returned by an OAuth provider.
 */
export interface OAuthUserInfo {
  providerId: string;
  email: string;
  name: string;
  picture?: string;
}

/**
 * Interface contract defining methods required for an OAuth authentication provider.
 */
export interface OAuthProvider {
  name: string;
  getAuthUrl: (state: string, codeVerifier?: string) => string;
  exchangeCode: (code: string, codeVerifier?: string) => Promise<OAuthUserInfo>;
}
