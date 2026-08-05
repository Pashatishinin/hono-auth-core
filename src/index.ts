export { createAuth } from './auth.js'
export { googleProvider } from './oauth/providers/google.js'
export type { GoogleProviderOptions } from './oauth/providers/google.js'
export { appleProvider } from './oauth/providers/apple.js'
export type { AppleProviderOptions } from './oauth/providers/apple.js'
export { oauth2Provider } from './oauth/providers/generic.js'
export type { GenericOAuthOptions } from './oauth/providers/generic.js'
export { signSessionToken, verifySessionToken } from './jwt.js'
export {
  getAccessTokenCookie,
  getRefreshTokenCookie,
  setSessionCookies,
  clearSessionCookies,
} from './cookies.js'
export { createMemorySessionStore } from './session/memoryStore.js'
export type {
  AuthConfig,
  CookieConfig,
  IdTokenVerificationConfig,
  JwtConfig,
  OAuthProfile,
  OAuthProvider,
  SessionMeta,
  SessionPayload,
  SessionStore,
} from './types.js'
