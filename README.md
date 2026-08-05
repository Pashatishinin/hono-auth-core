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
  async create(userId, meta) {
    /* insert a row, return { token: randomOpaqueToken, id: rowId } */
  },
  async rotate(presentedToken, meta) {
    /* look up presentedToken; if missing (already rotated/revoked), return null —
       that's a replay attempt and the caller fails closed. Otherwise delete the
       old row, insert a new token for the same userId, return { newToken, userId } */
  },
  async revoke(token) {
    /* delete the row */
  },
}
```

`rotate()` only needs to return `userId` — the reissued access token after a refresh
carries just `{ sub: userId }`, not the full `onSuccess` payload (role, email, ...). If your
app needs those on every request, re-derive them yourself (e.g. a DB lookup keyed by
`sub`) rather than relying on the refreshed access token to still carry them.

`meta` (`{ ip, userAgent }`, plus anything else you want) is passed through untouched on
every `create`/`rotate` call — store it if you want to build an "active sessions" UI.
`/auth/logout` calls `sessionStore.revoke()` on the current refresh token automatically when
a store is configured.

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
any query string on `/auth/:provider/login` round-trips through the OAuth flow (via a
short-lived httpOnly cookie, not the `state` URL param, so it isn't exposed to the provider
or the browser's address bar) and is handed back to both `beforeCreateUser` and `onSuccess`:

```html
<a href="/auth/google/login?inviteCode=abc123&returnTo=/dashboard">Sign up with Google</a>
```

## Publishing a new version

```bash
pnpm version patch   # or minor / major
git push --follow-tags
```

Pushing a `v*` tag triggers `.github/workflows/publish.yml`, which typechecks, builds, and
runs `pnpm publish` against npmjs.com, using the `NPM_TOKEN` repository secret.

To publish manually:

```bash
pnpm build
pnpm publish --no-git-checks
```
