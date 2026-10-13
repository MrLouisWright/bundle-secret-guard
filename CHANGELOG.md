# Changelog

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
