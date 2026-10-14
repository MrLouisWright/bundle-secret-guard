# Changelog

## 1.1.0 — 2026-10-14

- **gitleaks TOML**: load `[[rules]]` from gitleaks config files (`--gitleaks` / `config.gitleaks`) via a built-in TOML parser (zero runtime deps). Supports `extend.path`, rule allowlists, keywords, `secretGroup`, and entropy thresholds.
- **Entropy + baseline**: optional `--entropy-scan` / `config.entropyScan` for high-entropy quoted strings; baseline file (`--baseline`, detect-secrets or native JSON) with `--update-baseline` (stores SHA-256 hashes only).
- **Live verification (opt-in)**: `--verify` / `config.verify` checks GitHub, Stripe, OpenAI, Anthropic, and npm tokens against each provider’s own API only (off by default).
- **`bundle-secret-guard/patterns`**: export built-in `RULES`, gitleaks loaders, and `listBuiltinPatterns()` for reuse in other sentinel packages.
- **Dual ESM + CJS** builds (`exports` `import` / `require`), TypeScript declarations generated into `dist/` at build time.
- CI runs `npm run build`, tests include `require()` + `import()` of published entry points; release workflow unchanged (`npm publish --provenance`).

## 1.0.2 — 2026-10-13

- CI: harden workflows (actions pinned to SHAs, least-privilege permissions, persist-credentials: false)

## 1.0.0 — 2026-10-13

- Initial release.
- Scans built frontend output (`dist/`, `build/`, `out/`, `.next/static`, …) for `.js .mjs .cjs .css .html .map .json .txt .svg`.
- Provider rules: AWS, Stripe, GitHub, Slack, OpenAI, Anthropic, Google API keys, private keys, Firebase service accounts, privileged JWTs (Supabase `service_role`), Twilio, SendGrid, Mailgun, npm tokens, database URLs with credentials, generic high-entropy secrets.
- `.env` cross-check (`--env-file`), public-prefix awareness (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, …).
- Source map warning + `sourcesContent` scanning.
- Redacted output, JSON and SARIF 2.1.0, `--fail-on`, `--max-file-size`, `--public-prefix`, config file with allowlists, rule severities and custom patterns.
- Vite plugin, webpack plugin, programmatic API with TypeScript types, GitHub composite action.
