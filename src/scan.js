import { readdirSync, statSync, readFileSync, existsSync } from 'node:fs';
import { join, relative, extname, resolve } from 'node:path';
import { RULES, FILE_RULES, entropy, redact } from './rules.js';
import { loadGitleaksRules, lineMatchesKeywords, isGitleaksAllowed } from './gitleaks.js';
import { loadBaseline, isBaselined } from './baseline.js';
import { resolveGitleaksPaths, resolveBaselinePath } from './config.js';

export const DEFAULT_PUBLIC_PREFIXES = ['NEXT_PUBLIC_', 'VITE_', 'REACT_APP_', 'PUBLIC_', 'NUXT_PUBLIC_', 'EXPO_PUBLIC_', 'GATSBY_'];
export const DEFAULT_EXTENSIONS = ['.js', '.mjs', '.cjs', '.css', '.html', '.htm', '.map', '.json', '.txt', '.svg'];
export const DEFAULT_DIRS = ['dist', 'build', 'out', '.next/static', '.output/public', '.svelte-kit/output/client'];
const NON_SECRET_ENV = new Set(['NODE_ENV', 'PORT', 'HOST', 'HOSTNAME', 'TZ', 'LANG', 'CI', 'BASE_URL', 'PUBLIC_URL', 'MODE', 'DEV', 'PROD', 'SSR']);
const SEV = { off: -1, info: 0, warn: 1, error: 2 };

export function detectDirs(cwd = process.cwd()) {
  return DEFAULT_DIRS.filter((d) => existsSync(join(cwd, d)) && statSync(join(cwd, d)).isDirectory());
}

export function globToRegExp(g) {
  let r = '';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*' && g[i + 1] === '*') { r += '.*'; i++; if (g[i + 1] === '/') i++; }
    else if (c === '*') r += '[^/]*';
    else if (c === '?') r += '[^/]';
    else r += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`(^|/)${r}$`);
}

export function parseEnv(text) {
  const out = [];
  text.split(/\r?\n/).forEach((line, i) => {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)?$/);
    if (!m) return;
    let v = (m[2] || '').trim();
    if (/^["'`]/.test(v)) { const q = v[0]; const end = v.indexOf(q, 1); v = end > 0 ? v.slice(1, end) : v.slice(1); if (q === '"') v = v.replace(/\\n/g, '\n'); }
    else v = v.replace(/\s+#.*$/, '');
    out.push({ key: m[1], value: v, line: i + 1 });
  });
  return out;
}

function walk(dir, exts, files = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) { if (e.name !== 'node_modules') walk(p, exts, files); }
    else if (e.isFile() && exts.includes(extname(e.name).toLowerCase())) files.push(p);
  }
  return files;
}

function locator(text) {
  let starts = null;
  return (idx) => {
    if (!starts) { starts = [0]; for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1); }
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= idx) lo = mid; else hi = mid - 1; }
    return { line: lo + 1, column: idx - starts[lo] + 1 };
  };
}

function compileConfig(config = {}, opts = {}, cwd = process.cwd()) {
  const al = config.allowlist || {};
  const sev = { ...(config.severities || {}), ...(config.rules || {}) };
  for (const r of config.ignoreRules || config.ignore || []) sev[r] = 'off';

  const gitleaksPaths = resolveGitleaksPaths(config, opts);
  let gitleaksGlobalAllow = [];
  let gitleaksErrors = [];
  let gitleaksRules = [];
  if (gitleaksPaths.length) {
    const gl = loadGitleaksRules(gitleaksPaths, cwd);
    gitleaksRules = gl.rules;
    gitleaksGlobalAllow = gl.globalAllow;
    gitleaksErrors = gl.errors;
  }

  const custom = (config.customPatterns || config.patterns || []).map((p) => ({
    id: p.id, title: p.title || p.id, severity: p.severity || 'error', group: p.group,
    re: new RegExp(p.pattern, (p.flags || '').replace('g', '') + 'g'), fix: p.fix || 'Remove this value from client code and rotate it.', entropy: p.entropy,
  }));

  const baselinePath = resolveBaselinePath(config, opts);
  const baseline = loadBaseline(baselinePath, cwd);

  const entropyScan = config.entropyScan || {};
  const entropyEnabled = opts.entropyScan ?? entropyScan.enabled ?? false;

  return {
    allowValues: new Set(al.values || []),
    allowPatterns: (al.patterns || []).map((p) => new RegExp(p)),
    allowFiles: (al.files || []).map(globToRegExp),
    sev, rules: [...RULES, ...gitleaksRules, ...custom],
    gitleaksGlobalAllow,
    gitleaksErrors,
    baseline,
    baselinePath,
    entropyScan: {
      enabled: entropyEnabled,
      minLength: entropyScan.minLength ?? 20,
      minEntropy: entropyScan.minEntropy ?? 4.5,
    },
    publicPrefixes: [...DEFAULT_PUBLIC_PREFIXES, ...(config.publicPrefixes || []), ...(opts.publicPrefixes || [])],
    maxFileSize: opts.maxFileSize ?? config.maxFileSize ?? 5 * 1024 * 1024,
    exts: config.extensions || DEFAULT_EXTENSIONS,
    updateBaseline: !!opts.updateBaseline,
  };
}

function applyRuleOnText(text, rule, ctx, c, push, filePath) {
  if (rule.path && filePath && !rule.path.test(filePath)) return;
  const loc = locator(text);
  const lines = text.split('\n');
  const runOnLine = (lineText, lineOffset) => {
    if (rule.keywords?.length && !lineMatchesKeywords(lineText, rule.keywords)) return;
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(lineText))) {
      if (m[0].length === 0) { rule.re.lastIndex++; continue; }
      const secret = m[rule.group ?? 0] ?? m[0];
      if (rule.entropy != null && entropy(secret) < rule.entropy) continue;
      let extra = {};
      if (rule.check) { const r = rule.check(m); if (!r) continue; if (typeof r === 'object') extra = r; }
      if (isGitleaksAllowed(secret, m[0], rule.allowlists)) continue;
      if (isGitleaksAllowed(secret, m[0], c.gitleaksGlobalAllow)) continue;
      const idx = lineOffset + m.index + (rule.group ? m[0].indexOf(secret) : 0);
      push({ id: rule.id, title: rule.title, severity: rule.severity, fix: rule.fix, ...extra, secret, ...ctx, ...loc(idx) });
    }
  };
  if (rule.keywords?.length) {
    let offset = 0;
    for (const line of lines) {
      runOnLine(line, offset);
      offset += line.length + 1;
    }
  } else {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text))) {
      if (m[0].length === 0) { rule.re.lastIndex++; continue; }
      const secret = m[rule.group ?? 0] ?? m[0];
      if (rule.entropy != null && entropy(secret) < rule.entropy) continue;
      let extra = {};
      if (rule.check) { const r = rule.check(m); if (!r) continue; if (typeof r === 'object') extra = r; }
      if (isGitleaksAllowed(secret, m[0], rule.allowlists)) continue;
      if (isGitleaksAllowed(secret, m[0], c.gitleaksGlobalAllow)) continue;
      const idx = m.index + (rule.group ? m[0].indexOf(secret) : 0);
      push({ id: rule.id, title: rule.title, severity: rule.severity, fix: rule.fix, ...extra, secret, ...ctx, ...loc(idx) });
    }
  }
}

function scanEntropyStrings(text, ctx, c, push) {
  if (!c.entropyScan.enabled) return;
  const { minLength, minEntropy } = c.entropyScan;
  const loc = locator(text);
  const re = /["'`]([A-Za-z0-9+/=_-]{16,200})["'`]/g;
  let m;
  while ((m = re.exec(text))) {
    const secret = m[1];
    if (secret.length < minLength) continue;
    if (entropy(secret) < minEntropy) continue;
    if (/^(?:true|false|null|\d+)$/i.test(secret)) continue;
    push({
      id: 'entropy-string',
      title: 'High-entropy string in bundle',
      severity: 'warn',
      fix: 'If this is a credential, rotate it and move usage server-side. Otherwise add the value to allowlist.values or baseline.',
      secret,
      ...ctx,
      ...loc(m.index + 1),
    });
  }
}

function scanText(text, ctx, c, push, filePath) {
  for (const rule of c.rules) {
    if (c.sev[rule.id] === 'off') continue;
    applyRuleOnText(text, rule, ctx, c, push, filePath);
  }
  scanEntropyStrings(text, ctx, c, push);
  const loc = locator(text);
  for (const ev of ctx.envSecrets) {
    let i = text.indexOf(ev.value);
    while (i !== -1) {
      push({ ...FILE_RULES['env-leak'], secret: ev.value, message: `Value of ${ev.key} (from ${ev.file}) appears literally in the bundle.`, ...ctx, ...loc(i) });
      i = text.indexOf(ev.value, i + ev.value.length);
    }
  }
}

/**
 * Scan build output directories for leaked secrets.
 * @returns {{ findings: object[], files: string[], skipped: object[], dirs: string[], gitleaksErrors?: string[], baselineCandidates?: object[] }}
 */
export function scan(dirs, opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const config = opts.config || {};
  const c = compileConfig(config, opts, cwd);
  if (!dirs || !dirs.length) dirs = config.dirs?.length ? config.dirs : detectDirs(cwd);
  const findings = [], skipped = [], files = [], baselineCandidates = [];
  /** @type {{ finding: object, secret: string }[]} */
  const verifyItems = [];
  const wantVerify = !!(opts.verify ?? config.verify);
  const seen = new Set();
  const isPublic = (k) => c.publicPrefixes.some((p) => k.startsWith(p));
  const isAllowed = (s) => c.allowValues.has(s) || c.allowPatterns.some((r) => r.test(s));
  const push = (f) => {
    const sev = c.sev[f.id] || f.severity;
    if (sev === 'off' || isAllowed(f.secret)) return;
    if (c.baseline.entries.length && isBaselined(f, f.secret, c.baseline)) return;
    const key = `${f.id}|${f.file}|${f.source || ''}|${f.line}|${f.column}`;
    if (seen.has(key)) return; seen.add(key);
    if (c.updateBaseline) baselineCandidates.push({ finding: { ...f, severity: sev }, secret: f.secret });
    const { secret, ...rest } = f;
    const row = { ...rest, severity: sev, match: redact(secret), length: String(secret).length };
    if (wantVerify) verifyItems.push({ finding: row, secret });
    findings.push(row);
  };

  const envSecrets = [];
  for (const ef of [...(config.envFiles || []), ...(opts.envFiles || [])]) {
    const p = resolve(cwd, ef);
    if (!existsSync(p)) { if (opts.envFiles?.includes(ef)) throw Object.assign(new Error(`env file not found: ${ef}`), { code: 'ENOENT_ENV' }); continue; }
    for (const e of parseEnv(readFileSync(p, 'utf8'))) {
      if (e.value.length < 8 || isAllowed(e.value)) continue;
      if (isPublic(e.key)) {
        const ctx = { file: ef, envSecrets: [] };
        scanText(e.value, ctx, { ...c, rules: c.rules.filter((r) => r.severity === 'error') }, (f) => {
          if ((c.sev[f.id] || f.severity) !== 'error') return;
          push({ ...FILE_RULES['env-public-secret'], secret: e.value, file: ef, line: e.line, column: 1,
            message: `${e.key} is public (inlined into the bundle) but its value looks like a ${f.title}.` });
        }, ef);
      } else {
        if (NON_SECRET_ENV.has(e.key) || /^(true|false|\d+(\.\d+)?)$/i.test(e.value) || /^https?:\/\/[^@\s]+$/.test(e.value)) continue;
        envSecrets.push({ key: e.key, value: e.value, file: ef });
      }
    }
  }

  for (const d of dirs) {
    const abs = resolve(cwd, d);
    if (!existsSync(abs)) throw Object.assign(new Error(`directory not found: ${d}`), { code: 'ENOENT_DIR' });
    for (const p of walk(abs, c.exts)) {
      const rel = relative(cwd, p).split('\\').join('/') || p;
      if (c.allowFiles.some((r) => r.test(rel))) continue;
      const size = statSync(p).size;
      if (size > c.maxFileSize) { skipped.push({ file: rel, size, reason: 'max-file-size' }); continue; }
      files.push(rel);
      const text = readFileSync(p, 'utf8');
      const ctx = { file: rel, envSecrets };
      if (p.endsWith('.map')) {
        if (c.sev['source-map'] !== 'off') findings.push({ ...FILE_RULES['source-map'], severity: c.sev['source-map'] || 'warn', file: rel, line: 1, column: 1, message: 'Source map is deployed with the bundle; it exposes original source.' });
        let map = null; try { map = JSON.parse(text); } catch {}
        if (map && Array.isArray(map.sourcesContent)) {
          map.sourcesContent.forEach((src, i) => { if (typeof src === 'string') scanText(src, { ...ctx, source: map.sources?.[i] || `#${i}` }, c, push, rel); });
          continue;
        }
      }
      scanText(text, ctx, c, push, rel);
    }
  }
  const strong = new Set(findings.filter((f) => f.id !== 'generic-secret' && f.id !== 'entropy-string').map((f) => `${f.file}|${f.source || ''}|${f.line}|${f.column}`));
  for (let i = findings.length - 1; i >= 0; i--) {
    const f = findings[i];
    if ((f.id === 'generic-secret' || f.id === 'entropy-string') && strong.has(`${f.file}|${f.source || ''}|${f.line}|${f.column}`)) findings.splice(i, 1);
  }
  const order = { error: 0, warn: 1, info: 2 };
  findings.sort((a, b) => a.file.localeCompare(b.file) || order[a.severity] - order[b.severity] || a.line - b.line || a.column - b.column);
  const out = { dirs, files, skipped, findings };
  if (c.gitleaksErrors.length) out.gitleaksErrors = c.gitleaksErrors;
  if (c.updateBaseline) out.baselineCandidates = baselineCandidates;
  if (wantVerify) out._verifyItems = verifyItems;
  return out;
}

export function shouldFail(result, failOn = 'error') {
  if (failOn === 'none') return false;
  const min = SEV[failOn] ?? 2;
  return result.findings.some((f) => (SEV[f.severity] ?? 0) >= min && f.severity !== 'info');
}
