import type { OAuthProfile, OAuthProvider } from '../types.js'
import { createCodeChallenge, randomString } from '../pkce.js'

export interface AuthorizationRequest {
  url: string
  state: string
  codeVerifier?: string
}

export async function buildAuthorizationUrl(provider: OAuthProvider): Promise<AuthorizationRequest> {
  const state = randomString(24)
  const url = new URL(provider.authorizationUrl)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', provider.clientId)
  url.searchParams.set('redirect_uri', provider.redirectUri)
  url.searchParams.set('scope', provider.scope)
  url.searchParams.set('state', state)

  for (const [key, value] of Object.entries(provider.extraAuthParams ?? {})) {
    url.searchParams.set(key, value)
  }

  let codeVerifier: string | undefined
  if (provider.pkce !== false) {
    codeVerifier = randomString(48)
    const challenge = await createCodeChallenge(codeVerifier)
    url.searchParams.set('code_challenge', challenge)
    url.searchParams.set('code_challenge_method', 'S256')
  }

  return { url: url.toString(), state, codeVerifier }
}

interface TokenResponse {
  access_token: string
  token_type?: string
  expires_in?: number
  refresh_token?: string
  scope?: string
  id_token?: string
  [key: string]: unknown
}

export async function exchangeCodeForToken(
  provider: OAuthProvider,
  code: string,
  codeVerifier?: string
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: provider.redirectUri,
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
  })
  if (codeVerifier) body.set('code_verifier', codeVerifier)

  const res = await fetch(provider.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: body.toString(),
  })

  if (!res.ok) {
    throw new Error(`OAuth token exchange failed (${res.status}): ${await res.text()}`)
  }

  return (await res.json()) as TokenResponse
}

export async function fetchProfile(provider: OAuthProvider, accessToken: string): Promise<OAuthProfile> {
  const res = await fetch(provider.userinfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
  })

  if (!res.ok) {
    throw new Error(`OAuth userinfo fetch failed (${res.status}): ${await res.text()}`)
  }

  const raw = (await res.json()) as Record<string, unknown>
  return provider.mapProfile(raw)
}
