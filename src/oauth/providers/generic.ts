import type { OAuthProfile, OAuthProvider } from '../../types.js'

export interface GenericOAuthOptions {
  name: string
  authorizationUrl: string
  tokenUrl: string
  userinfoUrl: string
  clientId: string
  clientSecret: string
  redirectUri: string
  scope: string
  extraAuthParams?: Record<string, string>
  pkce?: boolean
  mapProfile: (raw: Record<string, unknown>) => OAuthProfile
}

/** Configure an arbitrary OAuth2 / OpenID Connect provider by supplying its endpoints. */
export function oauth2Provider(options: GenericOAuthOptions): OAuthProvider {
  return { ...options }
}
