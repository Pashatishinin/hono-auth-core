export interface OAuthProfile {
  id: string
  email?: string
  name?: string
  avatarUrl?: string
  raw: Record<string, unknown>
}

export interface OAuthProvider {
  /** Slug used in routes: /auth/:name/login, /auth/:name/callback */
  name: string
  authorizationUrl: string
  tokenUrl: string
  userinfoUrl: string
  clientId: string
  clientSecret: string
  redirectUri: string
  scope: string
  /** Extra query params merged into the authorization request. */
  extraAuthParams?: Record<string, string>
  /** Maps the raw userinfo response to a normalized profile. */
  mapProfile: (raw: Record<string, unknown>) => OAuthProfile
  /** Whether to use PKCE (recommended, on by default). */
  pkce?: boolean
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

export interface AuthConfig<TUser extends SessionPayload = SessionPayload> {
  jwt: JwtConfig
  providers: OAuthProvider[]
  cookies?: CookieConfig
  /** Base path the auth routes are mounted under, e.g. "/auth". Used to build default redirectUri if not set per-provider. */
  basePath?: string
  /** Called after a successful OAuth exchange; return the payload to embed in the session JWT. */
  onSuccess: (profile: OAuthProfile, providerName: string) => Promise<TUser> | TUser
  /** Called after a successful login, to decide where to redirect the browser. Defaults to "/". */
  redirectTo?: (payload: TUser, providerName: string) => Promise<string> | string
  /** Called when OAuth fails or is denied. Defaults to redirecting to "/?error=oauth_failed". */
  onError?: (error: unknown, providerName: string) => Promise<string> | string
}
