# bundle-secret-guard

[![npm](https://img.shields.io/npm/v/bundle-secret-guard.svg)](https://www.npmjs.com/package/bundle-secret-guard)
[![CI](https://github.com/MrLouisWright/bundle-secret-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/bundle-secret-guard/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![node >=18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![zero deps](https://img.shields.io/badge/dependencies-0-success)

Fail your build when **secrets or API keys end up in the JavaScript you ship to the browser**. Scans your built frontend (`dist/`, `build/`, `out/`, `.next/static`) — including source maps — for provider keys (AWS, Stripe, GitHub, OpenAI, Anthropic, Supabase `service_role`, …) and for any server-only `.env` value that got inlined. Import **gitleaks** rule files (TOML), optional **entropy + baseline** (detect-secrets style), and opt-in **live-key verification** (provider APIs only). Every finding is redacted and comes with a **specific fix** (Vite/Next/CRA/Netlify/Vercel hints). Zero runtime dependencies, Node ≥ 18, dual **ESM + CommonJS**, JSON and SARIF (GitHub code scanning) output, Vite and webpack plugins.

Tests live under [`test/`](test/) and run in [CI](.github/workflows/ci.yml) on Node 18/20/22 (including `require()` and `import()` of the built package).

## Install

```bash
npm i -D bundle-secret-guard        # or run ad-hoc after your build:
npx bundle-secret-guard dist
```

## Usage

```
bundle-secret-guard [dir...] [options]

  [dir...]                  Build directories (default: auto-detect dist, build, out, .next/static, .output/public, .svelte-kit/output/client)
  -e, --env-file <file>     .env file to cross-check (repeatable), e.g. -e .env -e .env.local -e .env.production
  -c, --config <file>       JSON config (default: .envleakrc.json / .bundlesecretguardrc.json / bundle-secret-guard.config.json if present)
      --fail-on <level>     error | warn | none   (default: error)
      --json                Print JSON results
      --sarif [file]        Print SARIF 2.1.0 (or write to file)
      --max-file-size <n>   Skip files bigger than n bytes (default 5mb; accepts 500kb, 10mb)
      --public-prefix <p>   Extra public env prefix (repeatable)
      --gitleaks <file>     gitleaks TOML rules (repeatable)
      --baseline <file>     Baseline JSON (suppress known hashed findings)
      --update-baseline     Write new findings to the baseline (hashes only)
      --entropy-scan        Extra high-entropy string detection
      --verify              Opt-in live-key check via each provider's API (off by default)
      --no-info             Hide info-level findings
```

Exit codes: `0` pass, `1` findings at/above `--fail-on`, `2` usage error. Colours are disabled when `NO_COLOR` is set or stdout is not a TTY (`FORCE_COLOR=1` forces them). Secrets are **never printed in full** — only the first 4 characters and the length.

> Some Node 20 releases intercept a literal `--env-file` argument themselves (`node: .env: not found`). Use the short form `-e .env` to be safe.

### Sample output

A Vite app that imported a Stripe secret key from client code, built with `sourcemap: true`:

```
$ npx bundle-secret-guard -e .env

dist/assets/index-DMZFQv-v.js
  ✖ error Stripe secret/restricted live key [stripe-secret-key]
          dist/assets/index-DMZFQv-v.js:1:720  sk_l…(36 chars)
          fix: Rotate the key immediately (Stripe Dashboard → Developers → API keys → Roll key) — anything that was deployed must be treated as leaked.
            Create PaymentIntents/Checkout Sessions in a server/API route; the browser only needs the pk_ publishable key.
            Netlify: set it as a non-public env var and use a Netlify Function. Vercel: set it in Project → Settings → Environment Variables (no public prefix) and read it in an API route.
  ✖ error Server-only env value found in bundle [env-leak]
          dist/assets/index-DMZFQv-v.js:1:720  sk_l…(36 chars)
          Value of STRIPE_SECRET (from .env) appears literally in the bundle.
          fix: Rotate the key immediately — anything that was deployed must be treated as leaked.
            Move the call that needs this key to a server/API route (Next.js: app/api/*/route.ts or a Server Action; Vite/CRA: a backend or serverless function) and call that from the browser.
            Never put secrets in NEXT_PUBLIC_ / VITE_ / REACT_APP_ / PUBLIC_ variables: they are inlined into the bundle.

dist/assets/index-DMZFQv-v.js.map
  ✖ error Stripe secret/restricted live key [stripe-secret-key]
          dist/assets/index-DMZFQv-v.js.map (../../src/main.js):1:17  sk_l…(36 chars)
          fix: ...
  ⚠ warn  Source map shipped [source-map]
          dist/assets/index-DMZFQv-v.js.map:1:1
          Source map is deployed with the bundle; it exposes original source.
          fix: Source maps expose your original source code (and anything in it).
            Vite: build.sourcemap = false or "hidden" and don't deploy *.map. Next.js: productionBrowserSourceMaps: false (default). CRA: GENERATE_SOURCEMAP=false.

3 file(s) scanned: 4 error(s), 1 warning(s)
```

A clean build:

```
✔ no secrets found in 2 file(s) (dist)

2 file(s) scanned: 0 errors, 0 warnings
```

## Rules

| id | severity | what |
|---|---|---|
| `aws-access-key-id` | error | `AKIA…` / `ASIA…` access key IDs |
| `aws-secret-access-key` | error | 40-char secret assigned to an `aws…`/`secret…` name |
| `stripe-secret-key` | error | `sk_live_…` / `rk_live_…` |
| `stripe-test-secret-key` | warn | `sk_test_…` / `rk_test_…` |
| `stripe-publishable-key` | info | `pk_live_…` / `pk_test_…` (public by design, never fails) |
| `github-token` | error | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_` |
| `slack-token` / `slack-webhook` | error | `xoxb-` `xoxp-` … and `hooks.slack.com/services/…` |
| `openai-api-key` | error | `sk-proj-…`, `sk-svcacct-…`, legacy `sk-…T3BlbkFJ…` |
| `anthropic-api-key` | error | `sk-ant-api03-…` |
| `google-api-key` | warn | `AIza…` (often public, e.g. Maps/Firebase — check restrictions) |
| `private-key` | error | `-----BEGIN … PRIVATE KEY-----` |
| `firebase-service-account` | error | service account JSON (`"type": "service_account"`) |
| `jwt-service-role` | error | JWT whose decoded payload has role `service_role` / `admin` (Supabase service key). Other JWTs → `jwt` info |
| `twilio-api-key` | error | `SK` + 32 hex |
| `sendgrid-api-key` | error | `SG.xxx.yyy` |
| `mailgun-api-key` | error | `key-` + 32 hex |
| `npm-token` | error | `npm_…` |
| `database-url` | error | `postgres://user:pass@…` (also mysql, mongodb(+srv), redis, amqp, mssql); placeholder passwords ignored |
| `generic-secret` | warn | high-entropy (Shannon ≥ 3.5) string ≥ 16 chars assigned to `secret`/`token`/`password`/`api_key`/… |
| `entropy-string` | warn | with `--entropy-scan`: quoted string ≥ 20 chars with Shannon ≥ 4.5 (allowlist/baseline apply) |
| `gitleaks:*` | error | rules loaded from gitleaks TOML (`--gitleaks` / `config.gitleaks`) |
| `source-map` | warn | `.map` file shipped; its `sourcesContent` is scanned too |
| `env-leak` | error | value of a **non-public** `.env` variable appears literally in the bundle |
| `env-public-secret` | warn | a `NEXT_PUBLIC_`/`VITE_`/… variable whose value looks like a secret ("you exposed a secret via a public prefix") |

Scanned extensions: `.js .mjs .cjs .css .html .htm .map .json .txt .svg`. `node_modules` is skipped.

### `.env` cross-check

With `-e .env -e .env.production`, every variable **without** a public prefix (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `PUBLIC_`, `NUXT_PUBLIC_`, `EXPO_PUBLIC_`, `GATSBY_`, plus `--public-prefix`) is searched for literally in the output. Values shorter than 8 characters, booleans, numbers, plain `http(s)://` URLs without credentials and well-known keys (`NODE_ENV`, `PORT`, …) are skipped.

## Config

`.envleakrc.json` (or `.bundlesecretguardrc.json`, `bundle-secret-guard.config.json`, or `--config <file>`):

```json
{
  "dirs": ["dist"],
  "envFiles": [".env", ".env.production"],
  "failOn": "error",
  "maxFileSize": 5242880,
  "publicPrefixes": ["MYAPP_PUBLIC_"],
  "allowlist": {
    "values": ["the-exact-value-that-is-fine"],
    "patterns": ["^pk_test_"],
    "files": ["dist/vendor/**", "**/*.LICENSE.txt"]
  },
  "ignoreRules": ["google-api-key"],
  "rules": { "generic-secret": "off", "stripe-test-secret-key": "error" },
  "customPatterns": [
    { "id": "acme-internal-key", "pattern": "ACME-[0-9A-F]{32}", "severity": "error", "title": "ACME internal key", "fix": "Call the ACME proxy instead." }
  ],
  "gitleaks": [".gitleaks.toml"],
  "baseline": ".secrets.baseline.json",
  "entropyScan": { "enabled": true, "minLength": 20, "minEntropy": 4.5 },
  "verify": false
}
```

Inline ignore comments are not supported (built files are generated) — use the allowlist or **baseline**.

### gitleaks TOML rules

Point at your existing gitleaks config (or a fragment with `[[rules]]`). Rules are merged with the built-in provider patterns; IDs are prefixed with `gitleaks:`.

```bash
npx bundle-secret-guard dist --gitleaks .gitleaks.toml
```

Supports `regex`, `secretGroup`, `entropy`, `keywords`, per-rule `[[rules.allowlists]]`, global `[[allowlists]]`, and `extend.path` to pull in another TOML file. `extend.useDefault` is not bundled — use `extend.path` to the upstream `gitleaks.toml` from the gitleaks repo if you need the full default rule set.

### Baseline (detect-secrets style)

Known false positives are stored as **SHA-256 hashes** (never plaintext secrets). Native format:

```json
{ "version": "1.0", "findings": [{ "id": "google-api-key", "file": "dist/maps.js", "line": 4, "column": 12, "hash": "…" }] }
```

detect-secrets `.secrets.baseline` JSON (`results` keyed by filename) is also accepted. Refresh with `npx bundle-secret-guard dist --baseline .secrets.baseline.json --update-baseline`.

### Live verification (opt-in)

With `"verify": true` or `--verify`, supported tokens are checked against **only** that provider’s API (GitHub, Stripe, OpenAI, Anthropic, npm). Nothing is sent to third-party scanners. Disabled by default.

## Vite

```js
// vite.config.js
import { defineConfig } from 'vite';
import bundleSecretGuard from 'bundle-secret-guard/vite';

export default defineConfig({
  plugins: [bundleSecretGuard({ envFiles: ['.env', '.env.production'] })],
});
```

Runs after the bundle is written (`closeBundle`) and throws, so `vite build` exits non-zero. Options: `dirs`, `envFiles`, `failOn`, `config`, `configFile`, `publicPrefixes`, `maxFileSize`, `verbose`.

## Next.js

Run it after `next build` (client output lives in `.next/static`; static exports in `out/`):

```json
{
  "scripts": {
    "build": "next build && bundle-secret-guard .next/static -e .env -e .env.production"
  }
}
```

## webpack (CRA, custom setups)

```js
// webpack.config.js
import { BundleSecretGuardPlugin } from 'bundle-secret-guard/webpack';
export default { /* ... */ plugins: [new BundleSecretGuardPlugin({ envFiles: ['.env'] })] };
```

For Create React App without ejecting: `"build": "react-scripts build && bundle-secret-guard build -e .env"`.

## CI

### GitHub Actions (action)

```yaml
# .github/workflows/bundle-secrets.yml
name: Bundle secrets
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci && npm run build
      - uses: MrLouisWright/bundle-secret-guard@v1
        with:
          dirs: dist
          env-files: .env.production
          sarif: bundle-secrets.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: bundle-secrets.sarif }
```

### GitHub Actions (npx)

```yaml
      - run: npm run build
      - run: npx bundle-secret-guard dist --fail-on error
```

Netlify / Vercel: append it to your build command (`npm run build && npx bundle-secret-guard`) so a leaking deploy fails before it goes live.

## API

```js
import { scan, shouldFail, pretty, toSarif, loadConfig, verifyFindings } from 'bundle-secret-guard';

const result = scan(['dist'], { envFiles: ['.env'], config: loadConfig(), gitleaks: ['.gitleaks.toml'], baseline: '.secrets.baseline.json' });
if (result._verifyItems?.length) await verifyFindings(result._verifyItems);
console.log(pretty(result));
if (shouldFail(result, 'error')) process.exit(1);
// result.findings: [{ id, title, severity, file, source?, line, column, match, verified?, fix }]
```

CommonJS: `const { scan } = require('bundle-secret-guard');`

### Reuse patterns in other packages

```js
import { RULES, loadGitleaksRules, listBuiltinPatterns } from 'bundle-secret-guard/patterns';
```

TypeScript types are generated into `dist/` at build time (`npm run build`).

## Releasing

```bash
npm version patch   # or minor / major — bumps package.json, commits and tags
git push --follow-tags
```

Then create a GitHub release from the new tag. `.github/workflows/release.yml` runs the tests on Node 22 and publishes to npmjs (`npm publish --provenance`, needs the `NPM_TOKEN` secret) and to GitHub Packages as `@mrlouiswright/bundle-secret-guard`. Versions that already exist are skipped. `prepack` runs `npm run build` so the tarball includes `dist/`. Move the `v1` tag to the new release so `uses: MrLouisWright/bundle-secret-guard@v1` picks it up (`git tag -f v1 && git push -f origin v1`).

## Part of a set

- [header-sentinel](https://www.npmjs.com/package/header-sentinel) — fail CI on missing/misconfigured HTTP security headers.
- [csp-forge](https://www.npmjs.com/package/csp-forge) — generate a Content-Security-Policy.
- **bundle-secret-guard** — fail the build when secrets ship to the browser.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
