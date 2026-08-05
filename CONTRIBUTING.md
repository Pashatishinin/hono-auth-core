# Contributing

## Local setup

```bash
pnpm install
pnpm typecheck
pnpm build
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
