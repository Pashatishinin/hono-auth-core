import type { OAuthProvider } from '../../types.js'

export interface GoogleProviderOptions {
  clientId: string
  clientSecret: string
  redirectUri: string
  /** Defaults to "openid email profile". */
  scope?: string
  /** Forces the account chooser / consent screen. Defaults to "select_account". */
  prompt?: string
}

export function googleProvider(options: GoogleProviderOptions): OAuthProvider {
  return {
    name: 'google',
    authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userinfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scope: options.scope ?? 'openid email profile',
    extraAuthParams: { prompt: options.prompt ?? 'select_account', access_type: 'offline' },
    mapProfile: (raw) => ({
      id: String(raw.sub),
      email: typeof raw.email === 'string' ? raw.email : undefined,
      name: typeof raw.name === 'string' ? raw.name : undefined,
      avatarUrl: typeof raw.picture === 'string' ? raw.picture : undefined,
      raw,
    }),
  }
}
