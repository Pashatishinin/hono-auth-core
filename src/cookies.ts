import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import type { Context } from 'hono'
import type { CookieConfig } from './types.js'

export const DEFAULT_ACCESS_COOKIE = 'auth_access_token'
export const DEFAULT_REFRESH_COOKIE = 'auth_refresh_token'

function resolve(config?: CookieConfig) {
  return {
    accessTokenName: config?.accessTokenName ?? DEFAULT_ACCESS_COOKIE,
    refreshTokenName: config?.refreshTokenName ?? DEFAULT_REFRESH_COOKIE,
    domain: config?.domain,
    path: config?.path ?? '/',
    secure: config?.secure ?? true,
    sameSite: config?.sameSite ?? 'Lax',
  } as const
}

export function setSessionCookies(
  c: Context,
  tokens: { accessToken: string; refreshToken?: string },
  config?: CookieConfig
) {
  const resolved = resolve(config)

  setCookie(c, resolved.accessTokenName, tokens.accessToken, {
    httpOnly: true,
    secure: resolved.secure,
    sameSite: resolved.sameSite,
    path: resolved.path,
    domain: resolved.domain,
  })

  if (tokens.refreshToken) {
    setCookie(c, resolved.refreshTokenName, tokens.refreshToken, {
      httpOnly: true,
      secure: resolved.secure,
      sameSite: resolved.sameSite,
      path: resolved.path,
      domain: resolved.domain,
    })
  }
}

export function getAccessTokenCookie(c: Context, config?: CookieConfig): string | undefined {
  return getCookie(c, resolve(config).accessTokenName)
}

export function getRefreshTokenCookie(c: Context, config?: CookieConfig): string | undefined {
  return getCookie(c, resolve(config).refreshTokenName)
}

export function clearSessionCookies(c: Context, config?: CookieConfig) {
  const resolved = resolve(config)
  deleteCookie(c, resolved.accessTokenName, { path: resolved.path, domain: resolved.domain })
  deleteCookie(c, resolved.refreshTokenName, { path: resolved.path, domain: resolved.domain })
}
