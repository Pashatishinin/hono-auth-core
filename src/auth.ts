import { Hono } from 'hono'
import type { Context, MiddlewareHandler } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { clearSessionCookies, getAccessTokenCookie, getRefreshTokenCookie, setSessionCookies } from './cookies.js'
import { signSessionToken, verifySessionToken } from './jwt.js'
import { buildAuthorizationUrl, exchangeCodeForToken, generatePkce, resolveProfile } from './oauth/client.js'
import { signOAuthState, verifyOAuthState } from './oauth/state.js'
import { randomString } from './pkce.js'
import type { AuthConfig, SessionMeta, SessionPayload } from './types.js'

const OAUTH_STATE_COOKIE_PREFIX = 'auth_oauth_state_'
const OAUTH_STATE_TTL_SECONDS = 600

interface Auth<TUser extends SessionPayload> {
  /** Mount under any base path, e.g. app.route('/auth', auth.routes). */
  routes: Hono
  /** Verifies the session cookie and sets it on the context; 401s otherwise. */
  middleware: () => MiddlewareHandler
  /** Reads and verifies the session without failing the request; returns null if absent/invalid. */
  getSession: (c: Context) => Promise<TUser | null>
  /**
   * Revokes every active session for this user ("log out all devices", or
   * after a password/email change). Requires `sessionStore` to be
   * configured — throws otherwise, since stateless JWT refresh tokens can't
   * be revoked early.
   */
  revokeAllSessions: (userId: string) => Promise<void>
}

declare module 'hono' {
  interface ContextVariableMap {
    authUser: unknown
  }
}

interface StateCookiePayload {
  state: string
  codeVerifier?: string
  extraState: Record<string, string>
}

function sessionMetaFromContext(c: Context): SessionMeta {
  return {
    ip: c.req.header('x-forwarded-for') ?? undefined,
    userAgent: c.req.header('user-agent') ?? undefined,
  }
}

async function readCallbackParams(c: Context): Promise<Record<string, string>> {
  if (c.req.method === 'POST') {
    const body = await c.req.parseBody()
    const params: Record<string, string> = {}
    for (const [key, value] of Object.entries(body)) {
      if (typeof value === 'string') params[key] = value
    }
    return params
  }
  return c.req.query()
}

export function createAuth<TUser extends SessionPayload = SessionPayload>(
  config: AuthConfig<TUser>
): Auth<TUser> {
  const providers = new Map(config.providers.map((p) => [p.name, p]))
  const accessTtl = config.jwt.accessTokenExpiresIn ?? '15m'
  const refreshTtl = config.jwt.refreshTokenExpiresIn ?? '30d'

  const routes = new Hono()

  routes.get('/:provider/login', async (c) => {
    const provider = providers.get(c.req.param('provider'))
    if (!provider) return c.json({ error: 'unknown_provider' }, 404)

    const extraState = c.req.query()
    const pkce = provider.pkce !== false ? await generatePkce() : undefined

    let state: string

    if (provider.responseMode === 'form_post') {
      // Providers that POST the callback do it cross-origin (e.g.
      // appleid.apple.com -> the app's own domain). Browsers don't attach
      // SameSite=Lax cookies to cross-site POSTs, so the usual
      // cookie-holds-the-expected-state approach never round-trips here.
      // Instead, the state param itself is a signed JWT carrying
      // codeVerifier + extraState — its signature is the CSRF defense, no
      // cookie required.
      state = await signOAuthState({ codeVerifier: pkce?.codeVerifier, extraState }, config.jwt)
    } else {
      state = randomString(24)
      const cookiePayload: StateCookiePayload = { state, codeVerifier: pkce?.codeVerifier, extraState }
      setCookie(c, OAUTH_STATE_COOKIE_PREFIX + provider.name, JSON.stringify(cookiePayload), {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
        path: '/',
        maxAge: OAUTH_STATE_TTL_SECONDS,
      })
    }

    const url = buildAuthorizationUrl(provider, state, pkce?.codeChallenge)
    return c.redirect(url)
  })

  async function handleCallback(c: Context) {
    const providerName = c.req.param('provider') ?? ''
    const provider = providers.get(providerName)
    if (!provider) return c.json({ error: 'unknown_provider' }, 404)

    const isFormPost = provider.responseMode === 'form_post'
    const stateCookieName = OAUTH_STATE_COOKIE_PREFIX + provider.name
    const stateCookieRaw = isFormPost ? undefined : getCookie(c, stateCookieName)
    if (!isFormPost) deleteCookie(c, stateCookieName, { path: '/' })

    try {
      const params = await readCallbackParams(c)
      const { code, state: returnedState, error: errorParam, user: appleUser } = params

      if (errorParam) throw new Error(`oauth_denied: ${errorParam}`)
      if (!code || !returnedState) throw new Error('missing_oauth_params')

      let codeVerifier: string | undefined
      let extraState: Record<string, string>

      if (isFormPost) {
        const statePayload = await verifyOAuthState(returnedState, config.jwt)
        codeVerifier = statePayload.codeVerifier
        extraState = statePayload.extraState
      } else {
        if (!stateCookieRaw) throw new Error('missing_oauth_params')
        const parsed = JSON.parse(stateCookieRaw) as StateCookiePayload
        if (returnedState !== parsed.state) throw new Error('state_mismatch')
        codeVerifier = parsed.codeVerifier
        extraState = parsed.extraState
      }

      const tokenResponse = await exchangeCodeForToken(provider, code, codeVerifier)
      const profile = await resolveProfile(provider, tokenResponse, appleUser ? { user: appleUser } : undefined)

      if (config.beforeCreateUser) {
        await config.beforeCreateUser(profile, provider.name, extraState)
      }
      const userPayload = await config.onSuccess(profile, provider.name, extraState)

      const accessToken = await signSessionToken(userPayload, config.jwt, accessTtl)
      const refreshToken = config.sessionStore
        ? (await config.sessionStore.create(userPayload, sessionMetaFromContext(c))).token
        : await signSessionToken(userPayload, config.jwt, refreshTtl)

      setSessionCookies(c, { accessToken, refreshToken }, config.cookies)

      const redirectTo = config.redirectTo ? await config.redirectTo(userPayload, provider.name) : '/'
      return c.redirect(redirectTo)
    } catch (err) {
      const redirectTo = config.onError ? await config.onError(err, providerName) : '/?error=oauth_failed'
      return c.redirect(redirectTo)
    }
  }

  routes.get('/:provider/callback', handleCallback)
  routes.post('/:provider/callback', handleCallback)

  routes.post('/refresh', async (c) => {
    const refreshToken = getRefreshTokenCookie(c, config.cookies)
    if (!refreshToken) return c.json({ error: 'missing_refresh_token' }, 401)

    if (config.sessionStore) {
      const rotated = await config.sessionStore.rotate(refreshToken, sessionMetaFromContext(c))
      if (!rotated) {
        clearSessionCookies(c, config.cookies)
        return c.json({ error: 'invalid_refresh_token' }, 401)
      }

      const accessToken = await signSessionToken(rotated.payload, config.jwt, accessTtl)
      setSessionCookies(c, { accessToken, refreshToken: rotated.newToken }, config.cookies)
      return c.json({ ok: true })
    }

    try {
      const payload = await verifySessionToken<TUser>(refreshToken, config.jwt)
      const accessToken = await signSessionToken(payload, config.jwt, accessTtl)
      setSessionCookies(c, { accessToken }, config.cookies)
      return c.json({ ok: true })
    } catch {
      clearSessionCookies(c, config.cookies)
      return c.json({ error: 'invalid_refresh_token' }, 401)
    }
  })

  routes.post('/logout', async (c) => {
    if (config.sessionStore) {
      const refreshToken = getRefreshTokenCookie(c, config.cookies)
      if (refreshToken) await config.sessionStore.revoke(refreshToken)
    }
    clearSessionCookies(c, config.cookies)
    return c.json({ ok: true })
  })

  async function getSession(c: Context): Promise<TUser | null> {
    const accessToken = getAccessTokenCookie(c, config.cookies)
    if (!accessToken) return null
    try {
      return await verifySessionToken<TUser>(accessToken, config.jwt)
    } catch {
      return null
    }
  }

  function middleware(): MiddlewareHandler {
    return async (c, next) => {
      const user = await getSession(c)
      if (!user) return c.json({ error: 'unauthorized' }, 401)
      c.set('authUser', user)
      await next()
    }
  }

  async function revokeAllSessions(userId: string): Promise<void> {
    if (!config.sessionStore) {
      throw new Error(
        'revokeAllSessions() requires a sessionStore — stateless JWT refresh tokens cannot be revoked early'
      )
    }
    await config.sessionStore.revokeAll(userId)
  }

  return { routes, middleware, getSession, revokeAllSessions }
}
