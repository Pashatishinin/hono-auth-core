import type { IdTokenVerificationConfig, OAuthProfile, OAuthProvider } from '../../types.js'

export interface GenericOAuthOptions {
  name: string
  authorizationUrl: string
  tokenUrl: string
  /** Required unless `idToken` is set — at least one profile source is needed. */
  userinfoUrl?: string
  clientId: string
  /** Static secret. Use `getClientSecret` instead for per-request secrets (e.g. a signed JWT). */
  clientSecret?: string
  getClientSecret?: () => Promise<string> | string
  redirectUri: string
  scope: string
  extraAuthParams?: Record<string, string>
  pkce?: boolean
  /** Set to "form_post" for providers that POST the callback instead of using a query string. */
  responseMode?: 'query' | 'form_post'
  /** Verify the token response's id_token and derive the profile from its claims instead of calling userinfoUrl. */
  idToken?: IdTokenVerificationConfig
  mapProfile: (raw: Record<string, unknown>) => OAuthProfile
}

/** Configure an arbitrary OAuth2 / OpenID Connect provider by supplying its endpoints. */
export function oauth2Provider(options: GenericOAuthOptions): OAuthProvider {
  return { ...options }
}
