import { and, eq } from 'drizzle-orm';
import { config } from '@/config';
import { db } from '@/db/index';
import { oauthAccounts, users } from '@/db/schema';
import type { OAuthProvider, OAuthUserInfo } from '@/types';

/**
 * Represents the token response payload returned by the Google OAuth endpoint.
 */
interface GoogleTokenResponse {
  access_token: string;
  expires_in?: number;
  token_type?: string;
}

/**
 * Represents the user profile response returned by the Google userinfo endpoint.
 */
interface GoogleUserInfoResponse {
  id: string | number;
  email: string;
  name?: string;
  picture?: string;
}

/**
 * Represents the token response payload returned by the GitHub OAuth endpoint.
 */
interface GitHubTokenResponse {
  access_token: string;
  token_type?: string;
  scope?: string;
}

/**
 * Represents the user profile response returned by the GitHub API.
 */
interface GitHubUserResponse {
  id: number;
  login: string;
  name?: string;
  email?: string;
  avatar_url?: string;
}

/**
 * Represents an email entry returned by the GitHub user emails API.
 */
interface GitHubEmailResponse {
  email: string;
  primary: boolean;
  verified: boolean;
}

/**
 * OAuth provider implementation for Google authentication.
 */
export class GoogleOAuthProvider implements OAuthProvider {
  name = 'google';

  /**
   * Generates the Google OAuth authorization URL.
   *
   * @param state - Anti-forgery state token.
   * @param codeVerifier - Optional PKCE code verifier.
   * @returns The full Google OAuth authorization URL.
   */
  getAuthUrl(state: string, codeVerifier?: string): string {
    const params = new URLSearchParams({
      client_id: config.googleClientId,
      redirect_uri: `${config.idpIssuer}/auth/google/callback`,
      response_type: 'code',
      scope: 'openid email profile',
      state,
      prompt: 'consent',
      access_type: 'offline',
    });
    if (codeVerifier) {
      params.set('code_challenge', codeVerifier);
      params.set('code_challenge_method', 'plain');
    }
    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  }

  /**
   * Exchanges an authorization code for Google user information.
   *
   * @param code - Authorization code received from Google callback.
   * @param codeVerifier - Optional PKCE code verifier.
   * @returns A promise resolving to the user profile information.
   * @throws Error if token exchange or user info fetch fails.
   */
  async exchangeCode(
    code: string,
    codeVerifier?: string,
  ): Promise<OAuthUserInfo> {
    const tokenParams: Record<string, string> = {
      code,
      client_id: config.googleClientId,
      client_secret: config.googleClientSecret,
      redirect_uri: `${config.idpIssuer}/auth/google/callback`,
      grant_type: 'authorization_code',
    };
    if (codeVerifier) {
      tokenParams.code_verifier = codeVerifier;
    }

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(tokenParams).toString(),
    });

    if (!tokenRes.ok) {
      const errorText = await tokenRes.text();
      throw new Error(`Google token exchange failed: ${errorText}`);
    }

    const tokenData = (await tokenRes.json()) as GoogleTokenResponse;
    const accessToken = tokenData.access_token;

    const userRes = await fetch(
      'https://www.googleapis.com/oauth2/v2/userinfo',
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    );

    if (!userRes.ok) {
      throw new Error('Failed to fetch Google user info');
    }

    const userData = (await userRes.json()) as GoogleUserInfoResponse;
    return {
      providerId: String(userData.id),
      email: userData.email,
      name: userData.name || userData.email.split('@')[0],
      picture: userData.picture,
    };
  }
}

/**
 * OAuth provider implementation for GitHub authentication.
 */
export class GitHubOAuthProvider implements OAuthProvider {
  name = 'github';

  /**
   * Generates the GitHub OAuth authorization URL.
   *
   * @param state - Anti-forgery state token.
   * @returns The full GitHub OAuth authorization URL.
   */
  getAuthUrl(state: string): string {
    const params = new URLSearchParams({
      client_id: config.githubClientId,
      redirect_uri: `${config.idpIssuer}/auth/github/callback`,
      scope: 'read:user user:email',
      state,
    });
    return `https://github.com/login/oauth/authorize?${params.toString()}`;
  }

  /**
   * Exchanges an authorization code for GitHub user information and primary email.
   *
   * @param code - Authorization code received from GitHub callback.
   * @returns A promise resolving to the user profile information.
   * @throws Error if token exchange or user info fetch fails.
   */
  async exchangeCode(code: string): Promise<OAuthUserInfo> {
    const tokenRes = await fetch(
      'https://github.com/login/oauth/access_token',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          client_id: config.githubClientId,
          client_secret: config.githubClientSecret,
          code,
        }),
      },
    );

    if (!tokenRes.ok) {
      throw new Error('GitHub token exchange failed');
    }

    const tokenData = (await tokenRes.json()) as GitHubTokenResponse;
    const accessToken = tokenData.access_token;

    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'User-Agent': 'UNSAReport-IDP',
      },
    });

    if (!userRes.ok) {
      throw new Error('Failed to fetch GitHub user info');
    }

    const userData = (await userRes.json()) as GitHubUserResponse;

    let { email } = userData;
    if (!email) {
      const emailRes = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'User-Agent': 'UNSAReport-IDP',
        },
      });
      if (emailRes.ok) {
        const emails = (await emailRes.json()) as GitHubEmailResponse[];
        const primary = emails.find((e) => e.primary) || emails[0];
        if (primary) {
          ({ email } = primary);
        }
      }
    }

    return {
      providerId: String(userData.id),
      email: email || `${userData.login}@users.noreply.github.com`,
      name: userData.name || userData.login,
      picture: userData.avatar_url,
    };
  }
}

/**
 * Registry for managing supported OAuth providers.
 */
export class OAuthProviderRegistry {
  private readonly providers = new Map<string, OAuthProvider>();

  /**
   * Initializes the registry with default OAuth providers (Google and GitHub).
   */
  constructor() {
    this.register(new GoogleOAuthProvider());
    this.register(new GitHubOAuthProvider());
  }

  /**
   * Registers an OAuth provider instance.
   *
   * @param provider - The OAuth provider instance to register.
   */
  register(provider: OAuthProvider) {
    this.providers.set(provider.name, provider);
  }

  /**
   * Retrieves a registered OAuth provider by name.
   *
   * @param name - The name of the OAuth provider.
   * @returns The OAuth provider instance, or undefined if not found.
   */
  get(name: string): OAuthProvider | undefined {
    return this.providers.get(name);
  }
}

export const providerRegistry = new OAuthProviderRegistry();

/**
 * Upserts a user and links their OAuth account record.
 *
 * @param provider - The OAuth provider name.
 * @param info - The user profile information retrieved from the OAuth provider.
 * @returns A promise resolving to the created or updated user record.
 */
export async function upsertOAuthUser(provider: string, info: OAuthUserInfo) {
  const [existingOAuth] = await db
    .select()
    .from(oauthAccounts)
    .where(
      and(
        eq(oauthAccounts.provider, provider),
        eq(oauthAccounts.providerId, info.providerId),
      ),
    );

  if (existingOAuth) {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, existingOAuth.userId));

    if (user) {
      const [updatedUser] = await db
        .update(users)
        .set({
          name: info.name || user.name,
          picture: info.picture || user.picture,
          updatedAt: new Date(),
        })
        .where(eq(users.id, user.id))
        .returning();

      return updatedUser;
    }
  }

  const [existingUserByEmail] = await db
    .select()
    .from(users)
    .where(eq(users.email, info.email));

  let user = existingUserByEmail;

  if (!user) {
    const [newUser] = await db
      .insert(users)
      .values({
        email: info.email,
        name: info.name,
        picture: info.picture || null,
      })
      .returning();
    user = newUser;
  }

  await db.insert(oauthAccounts).values({
    userId: user.id,
    provider,
    providerId: info.providerId,
  });

  return user;
}
