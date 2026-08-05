import { createRemoteJWKSet, jwtVerify } from 'jose'
import type { OAuthProvider } from '../types.js'

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

function getJwks(jwksUrl: string) {
  let jwks = jwksCache.get(jwksUrl)
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUrl))
    jwksCache.set(jwksUrl, jwks)
  }
  return jwks
}

/**
 * Verifies an id_token's signature against the provider's JWKS and checks
 * iss/aud, tolerating small clock skew (observed with Google, where the
 * id_token's `iat` can land a few seconds ahead of the verifying server's
 * clock). `clockTolerance` relaxes exp/nbf/iat timing checks without ever
 * skipping signature verification.
 */
export async function verifyIdToken(idToken: string, provider: OAuthProvider): Promise<Record<string, unknown>> {
  if (!provider.idToken) {
    throw new Error(`Provider "${provider.name}" is not configured for id_token verification`)
  }

  const jwks = getJwks(provider.idToken.jwksUrl)
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: provider.idToken.issuer,
    audience: provider.clientId,
    clockTolerance: provider.idToken.clockToleranceSeconds ?? 30,
  })

  return payload as Record<string, unknown>
}
