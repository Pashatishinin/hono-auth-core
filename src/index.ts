export { createAuth } from './auth.js'
export { googleProvider } from './oauth/providers/google.js'
export type { GoogleProviderOptions } from './oauth/providers/google.js'
export { oauth2Provider } from './oauth/providers/generic.js'
export type { GenericOAuthOptions } from './oauth/providers/generic.js'
export { signSessionToken, verifySessionToken } from './jwt.js'
export {
  getAccessTokenCookie,
  getRefreshTokenCookie,
  setSessionCookies,
  clearSessionCookies,
} from './cookies.js'
export type {
  AuthConfig,
  CookieConfig,
  JwtConfig,
  OAuthProfile,
  OAuthProvider,
  SessionPayload,
} from './types.js'
