import { SignJWT, jwtVerify } from 'jose'
import type { JwtConfig, SessionPayload } from './types.js'

function getKey(secret: string) {
  return new TextEncoder().encode(secret)
}

export async function signSessionToken(
  payload: SessionPayload,
  config: JwtConfig,
  expiresIn: string
): Promise<string> {
  let jwt = new SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime(expiresIn)

  if (config.issuer) jwt = jwt.setIssuer(config.issuer)
  if (config.audience) jwt = jwt.setAudience(config.audience)

  return jwt.sign(getKey(config.secret))
}

export async function verifySessionToken<TUser extends SessionPayload = SessionPayload>(
  token: string,
  config: JwtConfig
): Promise<TUser> {
  const { payload } = await jwtVerify(token, getKey(config.secret), {
    issuer: config.issuer,
    audience: config.audience,
  })
  return payload as unknown as TUser
}
