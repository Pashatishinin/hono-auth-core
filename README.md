# hono-auth-core

OAuth2 authentication core for [Hono](https://hono.dev), with a built-in Google preset, a
generic OAuth2/OIDC provider factory, PKCE, and JWT session cookies. Runs on any Hono runtime
(Node, Cloudflare Workers, Bun, Deno) — only Web Crypto and `fetch` are used.

## Install

Published publicly on npmjs.com — no token or `.npmrc` setup required.

```bash
pnpm add hono-auth-core hono
```

`hono` is a peer dependency.

## Quick start

```ts
import { Hono } from 'hono'
import { createAuth, googleProvider } from 'hono-auth-core'

const auth = createAuth({
  jwt: {
    secret: process.env.JWT_SECRET!,
    accessTokenExpiresIn: '15m',
    refreshTokenExpiresIn: '30d',
  },
  providers: [
    googleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      redirectUri: 'https://my-app.com/auth/google/callback',
    }),
  ],
  // Runs after a successful OAuth exchange. Upsert your own user record here
  // and return whatever payload should live inside the session JWT.
  onSuccess: async (profile) => ({
    sub: profile.id,
    email: profile.email,
    name: profile.name,
  }),
  redirectTo: () => '/dashboard',
})

const app = new Hono()

app.route('/auth', auth.routes)

app.use('/api/*', auth.middleware())
app.get('/api/me', (c) => c.json(c.get('authUser')))

export default app
```

This mounts:

- `GET /auth/google/login` — redirects to the provider's consent screen (PKCE + state are
  handled automatically via a short-lived httpOnly cookie).
- `GET /auth/google/callback` — exchanges the code, calls `onSuccess`, sets the session
  cookies, and redirects the browser via `redirectTo`.
- `POST /auth/refresh` — reads the refresh cookie and reissues an access token.
- `POST /auth/logout` — clears the session cookies.

## Generic OAuth2 / OIDC provider

For any provider that isn't Google, describe its endpoints once:

```ts
import { oauth2Provider } from 'hono-auth-core'

const github = oauth2Provider({
  name: 'github',
  authorizationUrl: 'https://github.com/login/oauth/authorize',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  userinfoUrl: 'https://api.github.com/user',
  clientId: process.env.GITHUB_CLIENT_ID!,
  clientSecret: process.env.GITHUB_CLIENT_SECRET!,
  redirectUri: 'https://my-app.com/auth/github/callback',
  scope: 'read:user user:email',
  mapProfile: (raw) => ({
    id: String(raw.id),
    email: raw.email as string | undefined,
    name: raw.name as string | undefined,
    avatarUrl: raw.avatar_url as string | undefined,
    raw,
  }),
})
```

Pass it in `providers: [github, ...]` alongside any other provider.

## Sign in with Apple

Apple's flow differs enough from a standard OAuth2 provider that it gets its own factory:
it POSTs the callback instead of using a query string, has no userinfo endpoint (identity
claims live in a verified `id_token`), only sends the user's name once (on first
authorization), and authenticates with a self-signed ES256 JWT instead of a static secret.
`appleProvider()` handles all of that:

```ts
import { appleProvider } from 'hono-auth-core'

appleProvider({
  teamId: process.env.APPLE_TEAM_ID!,
  keyId: process.env.APPLE_KEY_ID!,
  clientId: process.env.APPLE_SERVICES_ID!, // the "Services ID", used as client_id
  privateKey: process.env.APPLE_PRIVATE_KEY!, // .p8 contents, PEM format
  redirectUri: 'https://my-app.com/auth/apple/callback',
})
```

Because Apple POSTs the callback, `auth.routes` mounts `/:provider/callback` on both `GET`
and `POST` — no extra wiring needed on your end.

## Custom id_token verification

Any provider — including your own via `oauth2Provider()` — can resolve its profile from a
verified `id_token` instead of calling a userinfo endpoint, by setting `idToken` instead of
(or in addition to) `userinfoUrl`:

```ts
oauth2Provider({
  // ...
  idToken: {
    jwksUrl: 'https://example.com/.well-known/jwks.json',
    issuer: 'https://example.com',
    clockToleranceSeconds: 30, // default; guards against minor clock skew
  },
  mapProfile: (claims) => ({ id: String(claims.sub), email: claims.email as string, raw: claims }),
})
```

Verification uses [`jose`](https://github.com/panva/jose)'s `jwtVerify` with
`clockTolerance`, which relaxes exp/nbf/iat timing checks (useful since an id_token's `iat`
can occasionally land a few seconds ahead of the verifying server's clock — observed with
Google) without ever skipping signature verification.

## Sessions

Sessions are plain JWTs (HS256, via [`jose`](https://github.com/panva/jose)) stored in
httpOnly, `Secure`, `SameSite=Lax` cookies — no external session store required. Configure
cookie names/attributes via `cookies` in `createAuth`:

```ts
createAuth({
  // ...
  cookies: {
    accessTokenName: 'access_token',
    refreshTokenName: 'refresh_token',
    domain: '.my-app.com',
    sameSite: 'Lax',
  },
})
```

Read the session manually (e.g. outside middleware) with `auth.getSession(c)`, which returns
the typed payload or `null`.

`onSuccess` returns whatever payload you want embedded in the session — put a `role` or any
other claim in there, and it'll show up wherever `getSession`/`middleware()` read the session
back:

```ts
createAuth({
  // ...
  onSuccess: async (profile) => ({
    sub: profile.id,
    email: profile.email,
    role: await lookupRole(profile.email), // whatever your app needs
  }),
})
```

### Refresh-token rotation and revocation

By default, refresh tokens are stateless JWTs — simple, but there's no way to revoke a
session early (logout on one device doesn't affect others, and a stolen refresh token stays
valid until it expires). Pass a `sessionStore` to switch refresh tokens to opaque,
store-backed tokens that rotate on every use and can be revoked:

```ts
import { createAuth, createMemorySessionStore } from 'hono-auth-core'

createAuth({
  // ...
  sessionStore: createMemorySessionStore(), // dev-only — see below
})
```

`createMemorySessionStore()` is an in-memory implementation for local development or a
single-process server; it doesn't survive restarts or work across multiple instances. For
production, implement the `SessionStore` interface against your own database:

```ts
import type { SessionStore } from 'hono-auth-core'

const pgSessionStore: SessionStore = {
  async create(payload, meta) {
    /* insert a row keyed by payload.sub, storing whatever else of `payload`
       (role, email, ...) you want to persist; return { token: randomOpaqueToken, id: rowId } */
  },
  async rotate(presentedToken, meta) {
    /* look up presentedToken; if missing (already rotated/revoked), return null —
       that's a replay attempt and the caller fails closed. Otherwise delete the
       old row, insert a new token, and return { newToken, payload }. A real
       store should treat this as a chance to re-derive fresh claims (e.g. the
       user's current role) rather than just replaying what `create` stored —
       it already has to look the user up to validate the token anyway. */
  },
  async revoke(token) {
    /* delete the row */
  },
  async revokeAll(userId) {
    /* delete every row (or rotation "family") belonging to this userId —
       the only contract that matters is userId → every session dead,
       regardless of how you model sessions internally */
  },
}
```

`create()` receives the full session payload returned by `onSuccess` (not just the sub), and
`rotate()` returns the full payload back — so a refreshed access token carries the same
claims (role, email, ...) the original one did, not just `sub`. Store-backed sessions can
also do better than "carry forward what was originally stored": since `rotate()` already
needs to look the user up to validate the token, a real implementation can re-derive fresh
claims from your DB right there (e.g. pick up a role change without waiting for the user to
log out and back in).

`meta` (`{ ip, userAgent }`, plus anything else you want) is passed through untouched on
every `create`/`rotate` call — store it if you want to build an "active sessions" UI.
`/auth/logout` calls `sessionStore.revoke()` on the current refresh token automatically when
a store is configured.

To log a user out of every device at once (e.g. after a password change, or a suspected
account compromise), call `auth.revokeAllSessions(userId)` — it delegates to
`sessionStore.revokeAll()` so your app never has to reach into the store directly:

```ts
await auth.revokeAllSessions(userId)
```

This throws if no `sessionStore` is configured, since stateless JWT refresh tokens can't be
revoked early.

### Gating signup (invites, waitlists, etc.)

The package has no database and no opinion on how — or whether — you gate new signups. Wire
your own logic in via `beforeCreateUser`, which runs right before `onSuccess` on every login:

```ts
class InvalidInviteError extends Error {}

createAuth({
  // ...
  beforeCreateUser: async (profile, providerName, extraState) => {
    const existing = await db.findUserByEmail(profile.email)
    if (existing) return // returning user, nothing to gate

    const invite = await db.findInvite(extraState.inviteCode)
    if (!invite) throw new InvalidInviteError()
    await db.consumeInvite(invite.id)
  },
  onError: (err, providerName) => {
    if (err instanceof InvalidInviteError) return '/oops?reason=OAUTH_INVALID_INVITE'
    return '/?error=oauth_failed'
  },
})
```

Because the package has no persistence layer, it can't tell a first-time signup from a
returning login on its own — check that yourself inside the hook (as above), the same way
`onSuccess` already has to.

`extraState.inviteCode` comes from whatever query params were on the original login link —
any query string on `/auth/:provider/login` round-trips through the OAuth flow and is handed
back to both `beforeCreateUser` and `onSuccess`. For most providers this travels via a
short-lived httpOnly cookie (not the `state` URL param, so it isn't exposed to the provider
or the browser's address bar). Providers with `responseMode: "form_post"` (Apple) can't rely
on that cookie — browsers don't attach `SameSite=Lax` cookies to the cross-origin POST Apple
delivers the callback as — so for those, `extraState` (plus the PKCE `codeVerifier`) is
signed into the `state` param itself instead, using your `jwt.secret`, and verified on the
way back.

```html
<a href="/auth/google/login?inviteCode=abc123&returnTo=/dashboard">Sign up with Google</a>
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for local setup and how to cut a release.
