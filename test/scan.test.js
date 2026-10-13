import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scan, shouldFail, pretty, toSarif, parseEnv, redact, entropy, globToRegExp, vitePlugin, WebpackPlugin } from '../src/index.js';
import { FAKE } from './fake-keys.js';

const BIN = fileURLToPath(new URL('../bin/bundle-secret-guard.js', import.meta.url));
function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'bsg-'));
  for (const [p, c] of Object.entries(files)) { mkdirSync(join(dir, p, '..'), { recursive: true }); writeFileSync(join(dir, p), c); }
  return dir;
}
const ids = (r) => r.findings.map((f) => f.id);
const run = (cwd, args) => spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });

const cases = [
  ['aws-access-key-id', `const k="${FAKE.awsId}";`],
  ['aws-secret-access-key', `aws_secret_access_key:"${FAKE.awsSecret}"`],
  ['stripe-secret-key', `Stripe("${FAKE.stripeLive}")`],
  ['github-token', `t="${FAKE.github}"`],
  ['slack-token', `t="${FAKE.slack}"`],
  ['openai-api-key', `new OpenAI({apiKey:"${FAKE.openai}"})`],
  ['anthropic-api-key', `x="${FAKE.anthropic}"`],
  ['private-key', `const pem="${FAKE.pem}\\nMIIE..."`],
  ['firebase-service-account', FAKE.serviceAccount],
  ['jwt-service-role', `createClient(u,"${FAKE.jwtService}")`],
  ['twilio-api-key', `t="${FAKE.twilio}"`],
  ['sendgrid-api-key', `t="${FAKE.sendgrid}"`],
  ['mailgun-api-key', `t="${FAKE.mailgun}"`],
  ['npm-token', `t="${FAKE.npm}"`],
  ['database-url', `const db="${FAKE.dbUrl}"`],
];
for (const [id, code] of cases) {
  test(`detects ${id} as error`, () => {
    const d = fixture({ 'dist/assets/index.js': `(()=>{${code}})();` });
    const r = scan(['dist'], { cwd: d });
    const f = r.findings.find((x) => x.id === id);
    assert.ok(f, `expected ${id}, got ${ids(r)}`);
    assert.equal(f.severity, 'error');
    assert.equal(f.file, 'dist/assets/index.js');
    assert.equal(f.line, 1);
    assert.ok(shouldFail(r));
    rmSync(d, { recursive: true });
  });
}

test('warn / info level rules', () => {
  const d = fixture({ 'dist/a.js': `a="${FAKE.google}";b="${FAKE.stripePk}";c="${FAKE.jwtAnon}";const clientSecret="${FAKE.generic}";` });
  const r = scan(['dist'], { cwd: d });
  const sev = Object.fromEntries(r.findings.map((f) => [f.id, f.severity]));
  assert.equal(sev['google-api-key'], 'warn');
  assert.equal(sev['stripe-publishable-key'], 'info');
  assert.equal(sev.jwt, 'info');
  assert.equal(sev['generic-secret'], 'warn');
  assert.equal(shouldFail(r, 'error'), false);
  assert.equal(shouldFail(r, 'warn'), true);
  assert.equal(shouldFail(r, 'none'), false);
});

test('clean bundle has no findings; low-entropy & placeholders ignored', () => {
  const d = fixture({ 'dist/a.js': 'const password="aaaaaaaaaaaaaaaaaaaa";const u="postgres://user:password@localhost/db";const token=getToken();', 'dist/s.css': 'body{color:red}', 'dist/i.html': '<p>hi</p>' });
  const r = scan(['dist'], { cwd: d });
  assert.deepEqual(r.findings, []);
  assert.equal(r.files.length, 3);
});

test('never exposes the full secret', () => {
  const d = fixture({ 'dist/a.js': `x="${FAKE.stripeLive}"` });
  const r = scan(['dist'], { cwd: d });
  const out = JSON.stringify(r) + pretty(r, { color: false }) + JSON.stringify(toSarif(r));
  assert.ok(!out.includes(FAKE.stripeLive));
  assert.equal(r.findings[0].match, redact(FAKE.stripeLive));
  assert.match(r.findings[0].match, /^sk_l…\(\d+ chars\)$/);
});

test('reports correct line and column', () => {
  const d = fixture({ 'build/static/js/main.js': `line1\nline2\n   k="${FAKE.npm}"` });
  const f = scan(['build'], { cwd: d }).findings[0];
  assert.deepEqual([f.line, f.column], [3, 7]);
});

test('scans .mjs .css .html .json and nested dirs, skips node_modules', () => {
  const d = fixture({ 'out/a.mjs': FAKE.github, 'out/b.css': `/*${FAKE.npm}*/`, 'out/c.html': `<script>${FAKE.slack}</script>`, 'out/d/e.json': `{"k":"${FAKE.mailgun}"}`, 'out/node_modules/x.js': FAKE.github, 'out/img.png': FAKE.github });
  const r = scan(['out'], { cwd: d });
  assert.deepEqual([...new Set(r.findings.map((f) => f.file))].sort(), ['out/a.mjs', 'out/b.css', 'out/c.html', 'out/d/e.json']);
});

test('source maps: warns and scans sourcesContent with original source path', () => {
  const map = { version: 3, sources: ['../src/api.ts'], sourcesContent: [`// hi\nconst key = "${FAKE.openai}";`], mappings: '' };
  const d = fixture({ 'dist/a.js': 'x()', 'dist/a.js.map': JSON.stringify(map) });
  const r = scan(['dist'], { cwd: d });
  assert.ok(ids(r).includes('source-map'));
  const f = r.findings.find((x) => x.id === 'openai-api-key');
  assert.equal(f.source, '../src/api.ts');
  assert.deepEqual([f.line, f.column], [2, 14]);
});

test('.env cross-check: server-only values are errors, public secrets warn, short/public-safe skipped', () => {
  const d = fixture({
    '.env': `# comment\nDB_PASSWORD="${FAKE.envServer}"\nSHORT=abc12\nNODE_ENV=production\nAPI_URL=https://api.example.com\n`,
    '.env.production': `export VITE_STRIPE_KEY=${FAKE.stripeLive}\nVITE_TITLE=My great app\nNEXT_PUBLIC_SAFE=${FAKE.envServer}x\n`,
    'dist/a.js': `const p="${FAKE.envServer}";document.title="My great app";const e="production";fetch("https://api.example.com")`,
  });
  const r = scan(['dist'], { cwd: d, envFiles: ['.env', '.env.production'] });
  const leak = r.findings.filter((f) => f.id === 'env-leak');
  assert.equal(leak.length, 1);
  assert.equal(leak[0].severity, 'error');
  assert.match(leak[0].message, /DB_PASSWORD/);
  const pub = r.findings.filter((f) => f.id === 'env-public-secret');
  assert.equal(pub.length, 1);
  assert.equal(pub[0].file, '.env.production');
  assert.equal(pub[0].severity, 'warn');
});

test('custom public prefix', () => {
  const d = fixture({ '.env': `MYAPP_PUBLIC_X=${FAKE.envServer}`, 'dist/a.js': FAKE.envServer });
  assert.equal(scan(['dist'], { cwd: d, envFiles: ['.env'] }).findings.length, 1);
  assert.equal(scan(['dist'], { cwd: d, envFiles: ['.env'], publicPrefixes: ['MYAPP_PUBLIC_'] }).findings.length, 0);
});

test('config: allowlist values/patterns/files, ignoreRules, severities, custom patterns', () => {
  const d = fixture({ 'dist/a.js': `a="${FAKE.github}";b="${FAKE.npm}";c="${FAKE.google}";d="ACME-INTERNAL-0123456789"`, 'dist/vendor/v.js': FAKE.slack });
  const r = scan(['dist'], { cwd: d, config: {
    allowlist: { values: [FAKE.github], patterns: ['^npm_N9'], files: ['dist/vendor/**'] },
    rules: { 'google-api-key': 'error' },
    customPatterns: [{ id: 'acme-internal', pattern: 'ACME-INTERNAL-[0-9]{10}', severity: 'warn', fix: 'Use the proxy.' }],
  } });
  assert.deepEqual(ids(r).sort(), ['acme-internal', 'google-api-key']);
  assert.equal(r.findings.find((f) => f.id === 'google-api-key').severity, 'error');
  const r2 = scan(['dist'], { cwd: d, config: { ignoreRules: ['github-token', 'npm-token', 'google-api-key', 'slack-token'] } });
  assert.deepEqual(r2.findings, []);
});

test('max file size skips big files', () => {
  const d = fixture({ 'dist/big.js': 'x'.repeat(2000) + FAKE.github });
  const r = scan(['dist'], { cwd: d, maxFileSize: 1000 });
  assert.equal(r.findings.length, 0);
  assert.equal(r.skipped[0].file, 'dist/big.js');
});

test('helpers', () => {
  assert.deepEqual(parseEnv('A=1\nexport B="x y" \nC=\'q\' # c\nD=v # note\n#E=1'), [{ key: 'A', value: '1', line: 1 }, { key: 'B', value: 'x y', line: 2 }, { key: 'C', value: 'q', line: 3 }, { key: 'D', value: 'v', line: 4 }]);
  assert.ok(entropy('abcdefgh') > entropy('aaaaaaab'));
  assert.ok(globToRegExp('dist/**/*.map').test('dist/a/b/c.js.map'));
  assert.ok(!globToRegExp('*.map').test('a.js'));
});

test('SARIF output', () => {
  const d = fixture({ 'dist/a.js': FAKE.github });
  const s = toSarif(scan(['dist'], { cwd: d }));
  assert.equal(s.version, '2.1.0');
  assert.equal(s.runs[0].results[0].ruleId, 'github-token');
  assert.equal(s.runs[0].results[0].level, 'error');
  assert.equal(s.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'dist/a.js');
});

test('pretty output style and NO_COLOR', () => {
  const d = fixture({ 'dist/a.js': `${FAKE.github} ${FAKE.google}` });
  const r = scan(['dist'], { cwd: d });
  const out = pretty(r, { color: false });
  assert.match(out, /✖ error GitHub token \[github-token\]/);
  assert.match(out, /⚠ warn  Google API key \[google-api-key\]/);
  assert.match(out, /fix: Rotate the key immediately/);
  assert.match(out, /dist\/a\.js:1:1/);
  assert.match(out, /1 file\(s\) scanned: 1 error\(s\), 1 warning\(s\)/);
  assert.ok(!out.includes('\x1b['));
  assert.ok(pretty(r, { color: true }).includes('\x1b[31m'));
});

test('CLI: exit codes, auto-detect, --json, --sarif file, --fail-on, config file', () => {
  const d = fixture({ 'dist/a.js': FAKE.github, '.env': `SECRET_X=${FAKE.envServer}` });
  let p = run(d, []);
  assert.equal(p.status, 1, p.stderr);
  assert.match(p.stdout, /github-token/);
  assert.ok(!p.stdout.includes(FAKE.github));
  p = run(d, ['--json', '--fail-on', 'none']);
  assert.equal(p.status, 0);
  assert.equal(JSON.parse(p.stdout).findings[0].id, 'github-token');
  p = run(d, ['dist', '--sarif', 'out.sarif']);
  assert.equal(p.status, 1);
  assert.equal(JSON.parse(execFileSync('cat', [join(d, 'out.sarif')], { encoding: 'utf8' })).runs[0].results.length, 1);
  writeFileSync(join(d, '.envleakrc.json'), JSON.stringify({ allowlist: { values: [FAKE.github] } }));
  p = run(d, ['dist']);
  assert.equal(p.status, 0, p.stdout);
  writeFileSync(join(d, 'dist/b.js'), FAKE.envServer);
  assert.equal(run(d, ['dist', '-e', '.env']).status, 1);
  assert.equal(run(d, ['--bogus']).status, 2);
  assert.equal(run(d, ['--fail-on', 'nope']).status, 2);
  assert.equal(run(d, ['missing-dir']).status, 2);
  assert.equal(run(d, ['dist', '-e', '.env.missing']).status, 2);
  assert.equal(run(fixture({}), []).status, 2);
  assert.match(run(d, ['--version']).stdout, /^\d+\.\d+\.\d+/);
});

test('vite plugin throws on leak, passes when clean', () => {
  const d = fixture({ 'dist/a.js': FAKE.npm });
  const log = console.log; console.log = () => {};
  try {
    const p = vitePlugin();
    p.configResolved({ root: d, build: { outDir: 'dist' } });
    assert.throws(() => p.closeBundle.handler(), /secrets found/);
    writeFileSync(join(d, 'dist/a.js'), 'ok');
    p.closeBundle.handler();
  } finally { console.log = log; }
});

test('webpack plugin adds a compilation error', () => {
  const d = fixture({ 'build/main.js': FAKE.npm });
  let cb; const compiler = { context: d, outputPath: join(d, 'build'), hooks: { afterEmit: { tap: (_n, f) => { cb = f; } } } };
  new WebpackPlugin().apply(compiler);
  const compilation = { errors: [] };
  const log = console.log; console.log = () => {};
  try { cb(compilation); } finally { console.log = log; }
  assert.equal(compilation.errors.length, 1);
});
