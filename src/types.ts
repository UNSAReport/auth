export type Role = 'user' | 'admin';

export interface UserPayload {
  sub: string;
  email: string;
  name: string;
  picture?: string | null;
  roles?: Record<string, Role>;
}

export interface AccessTokenClaims extends UserPayload {
  roles: Record<string, Role>;
  iss: string;
  iat: number;
  exp: number;
  jti: string;
  type: 'access';
}

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  picture: string | null;
  createdAt: Date | null;
  updatedAt: Date | null;
}

export interface OAuthUserInfo {
  providerId: string;
  email: string;
  name: string;
  picture?: string;
}

export interface OAuthProvider {
  name: string;
  getAuthUrl: (state: string, codeVerifier?: string) => string;
  exchangeCode: (code: string, codeVerifier?: string) => Promise<OAuthUserInfo>;
}
