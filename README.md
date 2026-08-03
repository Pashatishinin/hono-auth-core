# @pashatishinin/hono-auth-core

OAuth2 authentication core for [Hono](https://hono.dev), with a built-in Google preset, a
generic OAuth2/OIDC provider factory, PKCE, and JWT session cookies. Runs on any Hono runtime
(Node, Cloudflare Workers, Bun, Deno) — only Web Crypto and `fetch` are used.

## Install

This package is published to GitHub Packages under the `@pashatishinin` scope.
GitHub Packages requires authentication even for public packages, so a token
is needed to install it — but the token itself must never be committed
anywhere (not in this README, not in `.npmrc`, not in git). Only an
environment-variable placeholder is safe to check in.

1. Generate a **classic** Personal Access Token with the `read:packages`
   scope: https://github.com/settings/tokens/new
2. In the *consuming* project (not this repo), add an `.npmrc` with a
   placeholder — safe to commit as-is:

   ```
   @pashatishinin:registry=https://npm.pkg.github.com
   //npm.pkg.github.com/:_authToken=${GH_PACKAGES_TOKEN}
   ```
3. Export the real token locally (e.g. in `~/.zshrc`), never in the repo:

   ```bash
   export GH_PACKAGES_TOKEN=your_token_here
   ```
4. Install:

   ```bash
   pnpm add @pashatishinin/hono-auth-core hono
   ```

`hono` is a peer dependency.

If install fails with `401`/`404`: confirm `echo $GH_PACKAGES_TOKEN` is set in
the shell you're running `pnpm` from, that `.npmrc` sits at the project root,
and that the token has the `read:packages` scope.

## Quick start

```ts
import { Hono } from 'hono'
import { createAuth, googleProvider } from '@pashatishinin/hono-auth-core'

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
import { oauth2Provider } from '@pashatishinin/hono-auth-core'

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

## Publishing a new version

```bash
pnpm version patch   # or minor / major
git push --follow-tags
```

Pushing a `v*` tag triggers `.github/workflows/publish.yml`, which typechecks, builds, and
runs `pnpm publish` against GitHub Packages.

To publish manually:

```bash
pnpm build
pnpm publish --no-git-checks
```
