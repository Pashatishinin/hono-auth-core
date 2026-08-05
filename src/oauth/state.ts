import { SignJWT, jwtVerify } from 'jose'
import type { JwtConfig } from '../types.js'

const OAUTH_STATE_TTL = '10m'

interface OAuthStateClaims {
  codeVerifier?: string
  extraState: Record<string, string>
}

function getKey(secret: string) {
  return new TextEncoder().encode(secret)
}

/**
 * Signs codeVerifier + extraState into a short-lived JWT used as the OAuth
 * `state` param itself, for providers that can't rely on a same-site cookie
 * round-trip (e.g. Apple's form_post callback is a cross-origin POST, which
 * browsers don't attach SameSite=Lax cookies to). The JWT's signature is the
 * CSRF defense — there's no separate "expected state" to compare against,
 * since only this server could have produced a validly-signed token.
 */
export async function signOAuthState(claims: OAuthStateClaims, jwt: JwtConfig): Promise<string> {
  return new SignJWT(claims as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(OAUTH_STATE_TTL)
    .sign(getKey(jwt.secret))
}

export async function verifyOAuthState(token: string, jwt: JwtConfig): Promise<OAuthStateClaims> {
  const { payload } = await jwtVerify(token, getKey(jwt.secret))
  return payload as unknown as OAuthStateClaims
}
