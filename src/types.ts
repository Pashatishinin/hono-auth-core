export interface OAuthProfile {
  id: string
  email?: string
  name?: string
  avatarUrl?: string
  raw: Record<string, unknown>
}

export interface IdTokenVerificationConfig {
  jwksUrl: string
  issuer: string
  /**
   * Seconds of leeway applied to exp/nbf/iat checks. Guards against providers
   * (observed with Google) whose id_token `iat` is occasionally a few
   * seconds ahead of the verifying server's clock.
   */
  clockToleranceSeconds?: number
}

export interface OAuthProvider {
  /** Slug used in routes: /auth/:name/login, /auth/:name/callback */
  name: string
  authorizationUrl: string
  tokenUrl: string
  clientId: string
  redirectUri: string
  scope: string
  /**
   * Static client secret. Mutually exclusive with `getClientSecret` — set
   * one or the other. Use `getClientSecret` for providers whose secret is
   * generated per-request (e.g. Apple's self-signed ES256 client-secret JWT).
   */
  clientSecret?: string
  getClientSecret?: () => Promise<string> | string
  /** Endpoint to GET the profile from using the access token as a bearer. */
  userinfoUrl?: string
  /** Verify the token response's `id_token` and derive the profile from its claims instead of calling userinfoUrl. */
  idToken?: IdTokenVerificationConfig
  /** Extra query params merged into the authorization request. */
  extraAuthParams?: Record<string, string>
  /** Maps the raw profile (userinfo JSON, or verified id_token claims) to a normalized profile. */
  mapProfile: (raw: Record<string, unknown>) => OAuthProfile
  /** Whether to use PKCE (recommended, on by default). */
  pkce?: boolean
  /** How the provider delivers the callback. Apple posts the code (response_mode=form_post) instead of a query string. Defaults to "query". */
  responseMode?: 'query' | 'form_post'
}

export interface JwtConfig {
  secret: string
  accessTokenExpiresIn?: string
  refreshTokenExpiresIn?: string
  issuer?: string
  audience?: string
}

export interface CookieConfig {
  accessTokenName?: string
  refreshTokenName?: string
  domain?: string
  path?: string
  secure?: boolean
  sameSite?: 'Strict' | 'Lax' | 'None'
}

export interface SessionPayload extends Record<string, unknown> {
  sub: string
}

/** Opaque, app-supplied context stored alongside a refresh token (e.g. for an "active sessions" UI). Passed through unchanged. */
export interface SessionMeta extends Record<string, unknown> {
  ip?: string
  userAgent?: string
}

/**
 * Pluggable refresh-token storage with rotation-on-use and revocation. When
 * omitted, `createAuth` falls back to stateless JWT refresh tokens (no
 * revocation, but no storage requirement either).
 */
export interface SessionStore {
  create: (userId: string, meta?: SessionMeta) => Promise<{ token: string; id: string }>
  /**
   * Exchanges a presented refresh token for a new one, invalidating the old
   * one. Must return null (and the caller must fail closed) if the token is
   * unknown or was already rotated away — that's a replay attempt.
   */
  rotate: (presentedToken: string, meta?: SessionMeta) => Promise<{ newToken: string; userId: string } | null>
  revoke: (token: string) => Promise<void>
}

export interface AuthConfig<TUser extends SessionPayload = SessionPayload> {
  jwt: JwtConfig
  providers: OAuthProvider[]
  cookies?: CookieConfig
  /** Base path the auth routes are mounted under, e.g. "/auth". Used to build default redirectUri if not set per-provider. */
  basePath?: string
  /**
   * Optional server-side refresh-token store. Without it, refresh tokens are
   * stateless JWTs (current default behavior). With it, refresh tokens are
   * opaque and rotate on every use, enabling early revocation (logout,
   * "log out all devices"). See `createMemorySessionStore` for a dev-only
   * default, or implement `SessionStore` against your own database.
   */
  sessionStore?: SessionStore
  /**
   * Runs before `onSuccess`, on every login. The package has no database of
   * its own, so it cannot tell a first-time signup from a returning login —
   * if you only want to gate new signups (e.g. invite codes), check that
   * inside this hook yourself (the same way `onSuccess` would). Throwing
   * aborts the login; the thrown value is passed to `onError` unchanged, so
   * a custom error class can be caught there with `instanceof`.
   */
  beforeCreateUser?: (
    profile: OAuthProfile,
    providerName: string,
    extraState: Record<string, string>
  ) => Promise<void> | void
  /**
   * Called after a successful OAuth exchange; return the payload to embed in
   * the session JWT. `extraState` carries whatever query params were present
   * on the original `/auth/:provider/login?...` request (e.g. `returnTo`,
   * an invite code) — see README for the round-trip mechanics.
   */
  onSuccess: (
    profile: OAuthProfile,
    providerName: string,
    extraState: Record<string, string>
  ) => Promise<TUser> | TUser
  /** Called after a successful login, to decide where to redirect the browser. Defaults to "/". */
  redirectTo?: (payload: TUser, providerName: string) => Promise<string> | string
  /** Called when OAuth fails or is denied. Defaults to redirecting to "/?error=oauth_failed". */
  onError?: (error: unknown, providerName: string) => Promise<string> | string
}
