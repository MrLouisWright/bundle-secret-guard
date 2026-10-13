// Built-in detection rules. Each rule: id, title, severity, regex (global), optional `group` (capture group
// holding the secret), optional `check(match)` returning false to drop or an object to override fields.
const H = {
  serverOnly: 'Move the call that needs this key to a server/API route (Next.js: app/api/*/route.ts or a Server Action; Vite/CRA: a backend or serverless function) and call that from the browser.',
  prefix: 'Never put secrets in NEXT_PUBLIC_ / VITE_ / REACT_APP_ / PUBLIC_ variables: they are inlined into the bundle.',
  hosts: 'Netlify: set it as a non-public env var and use a Netlify Function. Vercel: set it in Project → Settings → Environment Variables (no public prefix) and read it in an API route.',
};
const fix = (...l) => l.join('\n');
const rot = (where) => `Rotate the key immediately${where ? ` (${where})` : ''} — anything that was deployed must be treated as leaked.`;
H.rotate = rot();
const std = fix(H.rotate, H.serverOnly, H.prefix, H.hosts);

function b64json(s) {
  try { return JSON.parse(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); } catch { return null; }
}

export const RULES = [
  { id: 'private-key', title: 'Private key', severity: 'error', re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
    fix: fix('Private keys must never reach the browser. Remove the import/inlined file, sign on the server instead.', H.rotate) },
  { id: 'firebase-service-account', title: 'Google/Firebase service account JSON', severity: 'error', re: /"type"\s*:\s*"service_account"/g,
    fix: fix('Service account credentials grant admin access. Use the Firebase client config (apiKey, projectId...) in the browser and firebase-admin only on the server.', H.rotate) },
  { id: 'aws-access-key-id', title: 'AWS access key ID', severity: 'error', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    fix: fix(rot('IAM → Security credentials → deactivate'), 'Use pre-signed URLs or Cognito identity pools from the browser; keep IAM keys server-side.', H.prefix) },
  { id: 'aws-secret-access-key', title: 'AWS secret access key', severity: 'error', group: 1,
    re: /(?:aws|secret)[A-Za-z0-9_$.-]{0,30}["']?\s*[:=]\s*["'`]([A-Za-z0-9/+]{40})["'`]/gi,
    check: (m) => /[A-Z]/.test(m[1]) && /[a-z]/.test(m[1]) && /[0-9/+]/.test(m[1]), fix: std },
  { id: 'stripe-secret-key', title: 'Stripe secret/restricted live key', severity: 'error', re: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g,
    fix: fix(rot('Stripe Dashboard → Developers → API keys → Roll key'), 'Create PaymentIntents/Checkout Sessions in a server/API route; the browser only needs the pk_ publishable key.', H.hosts) },
  { id: 'stripe-test-secret-key', title: 'Stripe secret test key', severity: 'warn', re: /\b(?:sk|rk)_test_[0-9A-Za-z]{20,}\b/g,
    fix: fix('Test keys are not live money, but a shipped sk_test_ means your live key will be shipped the same way.', H.serverOnly) },
  { id: 'stripe-publishable-key', title: 'Stripe publishable key (public, OK)', severity: 'info', re: /\bpk_(?:live|test)_[0-9A-Za-z]{20,}\b/g,
    fix: 'Publishable keys are designed to be public. No action needed.' },
  { id: 'github-token', title: 'GitHub token', severity: 'error', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g,
    fix: fix(rot('github.com/settings/tokens'), 'GitHub may already have revoked it via secret scanning.', H.serverOnly) },
  { id: 'slack-token', title: 'Slack token', severity: 'error', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, fix: std },
  { id: 'slack-webhook', title: 'Slack incoming webhook URL', severity: 'error', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g, fix: std },
  { id: 'anthropic-api-key', title: 'Anthropic API key', severity: 'error', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g,
    fix: fix(rot('console.anthropic.com → API keys'), 'Proxy model calls through a server/API route; never call the API directly from the browser with your key.', H.prefix) },
  { id: 'openai-api-key', title: 'OpenAI API key', severity: 'error',
    re: /\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})/g,
    fix: fix(rot('platform.openai.com → API keys'), 'Proxy model calls through a server/API route (Next.js route handler, Netlify/Vercel function).', H.prefix) },
  { id: 'google-api-key', title: 'Google API key', severity: 'warn', re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    fix: fix('Often intentionally public (Maps, Firebase web config). Make sure it is restricted by HTTP referrer and API in Google Cloud Console → Credentials.', 'If it is an unrestricted server key, rotate it and move the call server-side.') },
  { id: 'jwt-service-role', title: 'JWT with privileged role (e.g. Supabase service_role)', severity: 'error',
    re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}/g,
    check: (m) => {
      const p = b64json(m[0].split('.')[1]);
      if (!p || typeof p !== 'object') return false;
      const role = String(p.role || p.roles || '');
      if (/service_role|admin|superuser/i.test(role)) return { message: `JWT payload has role "${role}" — this bypasses row level security.` };
      return { id: 'jwt', title: 'JWT in bundle', severity: 'info', message: `JWT payload role "${role || 'n/a'}"${p.exp ? `, exp ${new Date(p.exp * 1000).toISOString().slice(0, 10)}` : ''}.`,
        fix: 'Anon/public JWTs (e.g. Supabase anon key) are fine; make sure this is not a user or service token.' };
    },
    fix: fix(rot('Supabase: Project Settings → API → regenerate JWT secret / service_role key'), 'Use the anon key in the browser and the service_role key only in server code (API routes, Edge Functions).', H.prefix) },
  { id: 'twilio-api-key', title: 'Twilio API key / auth token', severity: 'error', re: /\bSK[0-9a-f]{32}\b/g, fix: std },
  { id: 'sendgrid-api-key', title: 'SendGrid API key', severity: 'error', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    fix: fix(H.rotate, 'Send email from a server/API route, never from the browser.', H.hosts) },
  { id: 'mailgun-api-key', title: 'Mailgun API key', severity: 'error', re: /\bkey-[0-9a-f]{32}\b/g,
    fix: fix(H.rotate, 'Send email from a server/API route, never from the browser.') },
  { id: 'npm-token', title: 'npm access token', severity: 'error', re: /\bnpm_[A-Za-z0-9]{36}\b/g,
    fix: fix(rot('npmjs.com → Access Tokens'), 'An .npmrc or CI variable leaked into the build; check your bundler define/env config.') },
  { id: 'database-url', title: 'Database URL with credentials', severity: 'error', group: 0,
    re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql):\/\/([^\s:@/"'`]+):([^\s@/"'`]+)@[^\s"'`<>]+/g,
    check: (m) => !/^(?:\$\{.*\}|<.*>|\*+|x+|pass(?:word)?|secret|changeme|\.\.\.)$/i.test(m[2]) && !/^(?:user(?:name)?)$/i.test(m[1]) || false,
    fix: fix('Database credentials must stay on the server. Query the database from an API route / server component.', rot('change the database user password'), H.prefix) },
  { id: 'generic-secret', title: 'High-entropy value assigned to a secret-looking name', severity: 'warn', group: 2, entropy: 3.5,
    re: /["']?([A-Za-z0-9_$.-]*(?:secret|token|passw(?:or)?d|passwd|api[_-]?key|apikey|private[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?key)[A-Za-z0-9_$-]*)["']?\s*[:=]\s*["'`]([^"'`\s]{16,200})["'`]/gi,
    fix: fix('If this is a real credential: rotate it immediately.', H.serverOnly, 'If it is not a secret, add it to allowlist.values or allowlist.patterns in .envleakrc.json.') },
];

export const FILE_RULES = {
  'source-map': { id: 'source-map', title: 'Source map shipped', severity: 'warn',
    fix: fix('Source maps expose your original source code (and anything in it).', 'Vite: build.sourcemap = false or "hidden" and don\'t deploy *.map. Next.js: productionBrowserSourceMaps: false (default). CRA: GENERATE_SOURCEMAP=false.', 'Or upload maps to your error tracker (Sentry) and delete them before deploy.') },
  'env-leak': { id: 'env-leak', title: 'Server-only env value found in bundle', severity: 'error', fix: std },
  'env-public-secret': { id: 'env-public-secret', title: 'You exposed a secret via a public prefix', severity: 'warn',
    fix: fix('This public-prefixed variable is inlined into the browser bundle but its value looks like a secret.', 'Rename it without the public prefix and read it only in server code; then rotate it.') },
};

export function entropy(s) {
  const f = {}; for (const c of s) f[c] = (f[c] || 0) + 1;
  let h = 0; for (const k in f) { const p = f[k] / s.length; h -= p * Math.log2(p); }
  return h;
}

export function redact(s) { s = String(s); return `${s.slice(0, 4)}…(${s.length} chars)`; }
