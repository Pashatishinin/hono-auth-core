import { SignJWT, importPKCS8 } from 'jose'
import type { OAuthProvider } from '../../types.js'

export interface AppleProviderOptions {
  /** Your Apple Developer Team ID. */
  teamId: string
  /** The Key ID of the Sign in with Apple private key (.p8). */
  keyId: string
  /** The Services ID configured for Sign in with Apple ("client_id"). */
  clientId: string
  /** PEM contents of the .p8 private key downloaded from Apple. */
  privateKey: string
  redirectUri: string
  /** Defaults to "name email". */
  scope?: string
  /** Client-secret JWT lifetime in seconds. Apple allows up to ~6 months; short-lived (regenerated per request) is safer. Defaults to 300. */
  clientSecretTtlSeconds?: number
}

function safeJsonParse(value: string): Record<string, unknown> | undefined {
  try {
    return JSON.parse(value) as Record<string, unknown>
  } catch {
    return undefined
  }
}

async function generateAppleClientSecret(options: AppleProviderOptions): Promise<string> {
  const key = await importPKCS8(options.privateKey, 'ES256')
  const now = Math.floor(Date.now() / 1000)
  const ttl = options.clientSecretTtlSeconds ?? 300

  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: options.keyId })
    .setIssuer(options.teamId)
    .setSubject(options.clientId)
    .setAudience('https://appleid.apple.com')
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .sign(key)
}

/**
 * Sign in with Apple. Unlike the generic OAuth2 flow, Apple:
 *  - POSTs the callback (response_mode=form_post) instead of a GET query string
 *  - has no userinfo endpoint — identity claims live in the id_token
 *  - only sends the user's name/email once, as a `user` JSON field on the
 *    very first authorization; the package forwards that into `mapProfile`
 *    as `raw.user`
 *  - authenticates with a self-signed ES256 client-secret JWT instead of a
 *    static secret, regenerated per request via `getClientSecret`
 *
 * PKCE is left off by default — Apple's authorize endpoint doesn't document
 * support for it.
 */
export function appleProvider(options: AppleProviderOptions): OAuthProvider {
  return {
    name: 'apple',
    authorizationUrl: 'https://appleid.apple.com/auth/authorize',
    tokenUrl: 'https://appleid.apple.com/auth/token',
    clientId: options.clientId,
    redirectUri: options.redirectUri,
    scope: options.scope ?? 'name email',
    pkce: false,
    responseMode: 'form_post',
    extraAuthParams: { response_mode: 'form_post' },
    getClientSecret: () => generateAppleClientSecret(options),
    idToken: {
      jwksUrl: 'https://appleid.apple.com/auth/keys',
      issuer: 'https://appleid.apple.com',
    },
    mapProfile: (raw) => {
      const userJson = typeof raw.user === 'string' ? safeJsonParse(raw.user) : undefined
      const nameParts = userJson?.name as { firstName?: string; lastName?: string } | undefined
      const name = nameParts ? [nameParts.firstName, nameParts.lastName].filter(Boolean).join(' ') : undefined

      return {
        id: String(raw.sub),
        email: typeof raw.email === 'string' ? raw.email : undefined,
        name: name || undefined,
        raw,
      }
    },
  }
}
