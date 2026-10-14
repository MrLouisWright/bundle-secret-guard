#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { scan, shouldFail, detectDirs, DEFAULT_DIRS } from '../dist/index.js';
import { pretty } from '../dist/format.js';
import { toSarif } from '../dist/sarif.js';
import { loadConfig, CONFIG_FILES } from '../dist/config.js';
import { updateBaseline, writeBaseline, loadBaseline } from '../dist/baseline.js';
import { verifyFindings } from '../dist/verify.js';

const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url))).version;
const HELP = `bundle-secret-guard [dir...] [options]

Scan built frontend output and fail when secrets / API keys were shipped to the browser.

Options:
  [dir...]                  Build directories (default: auto-detect ${DEFAULT_DIRS.join(', ')})
  -e, --env-file <file>     .env file to cross-check (repeatable), e.g. .env .env.local .env.production
  -c, --config <file>       JSON config (default: ${CONFIG_FILES.join(' / ')} if present)
      --gitleaks <file>     gitleaks TOML rules (repeatable); merges with config gitleaks path(s)
      --baseline <file>     Baseline JSON (detect-secrets or bundle-secret-guard format)
      --update-baseline     Add current findings to the baseline file (hashed secrets only)
      --entropy-scan        Enable extra high-entropy string detection (detect-secrets style)
      --verify              Opt-in: check whether keys are live via each provider's own API (off by default)
      --fail-on <level>     error | warn | none   (default: error)
      --json                Print JSON results
      --sarif [file]        Print SARIF 2.1.0 (or write to file) for GitHub code scanning
      --max-file-size <n>   Skip files bigger than n bytes (default: 5242880; accepts 10mb, 500kb)
      --public-prefix <p>   Extra public env prefix (repeatable)
      --no-info             Hide info-level findings in pretty output
  -h, --help / -v, --version

Exit codes: 0 pass, 1 findings at/above --fail-on, 2 usage error.`;

function die(m) { console.error(`bundle-secret-guard: ${m}\n\n${HELP}`); process.exit(2); }
function size(s) {
  const m = String(s).toLowerCase().match(/^(\d+(?:\.\d+)?)\s*(b|kb|k|mb|m|gb|g)?$/);
  if (!m) die(`invalid --max-file-size "${s}"`);
  return Math.round(Number(m[1]) * ({ k: 1024, kb: 1024, m: 1048576, mb: 1048576, g: 1073741824, gb: 1073741824 }[m[2]] || 1));
}
function parse(argv) {
  const o = { dirs: [], envFiles: [], publicPrefixes: [], gitleaks: [], info: true };
  for (let i = 0; i < argv.length; i++) {
    let a = argv[i], inline;
    if (a.startsWith('--') && a.includes('=')) { inline = a.slice(a.indexOf('=') + 1); a = a.slice(0, a.indexOf('=')); }
    const next = () => { if (inline !== undefined) return inline; if (i + 1 >= argv.length) die(`${a} requires a value`); return argv[++i]; };
    if (a === '-h' || a === '--help') { console.log(HELP); process.exit(0); }
    else if (a === '-v' || a === '--version') { console.log(VERSION); process.exit(0); }
    else if (a === '-e' || a === '--env-file') o.envFiles.push(next());
    else if (a === '-c' || a === '--config') o.config = next();
    else if (a === '--gitleaks') o.gitleaks.push(next());
    else if (a === '--baseline') o.baseline = next();
    else if (a === '--update-baseline') o.updateBaseline = true;
    else if (a === '--entropy-scan') o.entropyScan = true;
    else if (a === '--verify') o.verify = true;
    else if (a === '--fail-on') o.failOn = next();
    else if (a === '--json') o.json = true;
    else if (a === '--sarif') { o.sarif = true; if (inline) o.sarifFile = inline; else if (argv[i + 1] && !argv[i + 1].startsWith('-') && /\.(sarif|json)$/i.test(argv[i + 1])) o.sarifFile = argv[++i]; }
    else if (a === '--max-file-size') o.maxFileSize = size(next());
    else if (a === '--public-prefix') o.publicPrefixes.push(next());
    else if (a === '--no-info') o.info = false;
    else if (a.startsWith('-')) die(`unknown option ${a}`);
    else o.dirs.push(a);
  }
  return o;
}

const o = parse(process.argv.slice(2));
let config;
try { config = loadConfig(o.config); } catch (e) { die(`cannot read config ${o.config || ''}: ${e.message}`); }
const failOn = o.failOn || config.failOn || 'error';
if (!['error', 'warn', 'none'].includes(failOn)) die('--fail-on must be error, warn or none');
const dirs = o.dirs.length ? o.dirs : config.dirs?.length ? config.dirs : detectDirs();
if (!dirs.length) die(`no build directory found (looked for ${DEFAULT_DIRS.join(', ')}); pass one explicitly`);

let result;
try {
  result = scan(dirs, {
    config, envFiles: o.envFiles, publicPrefixes: o.publicPrefixes, maxFileSize: o.maxFileSize,
    gitleaks: o.gitleaks, baseline: o.baseline, updateBaseline: o.updateBaseline, entropyScan: o.entropyScan, verify: o.verify,
  });
} catch (e) { if (/^ENOENT_/.test(e.code)) die(e.message); throw e; }

if (result.gitleaksErrors?.length) {
  for (const msg of result.gitleaksErrors) console.error(`bundle-secret-guard: gitleaks: ${msg}`);
}

if (result._verifyItems?.length) {
  await verifyFindings(result._verifyItems);
  delete result._verifyItems;
}

const baselineFile = o.baseline || config.baseline;
if (o.updateBaseline) {
  if (!baselineFile) die('--update-baseline requires --baseline or config.baseline');
  const loaded = loadBaseline(baselineFile);
  const data = updateBaseline(loaded.raw, result.baselineCandidates || []);
  writeBaseline(baselineFile, data);
  delete result.baselineCandidates;
}

const failed = shouldFail(result, failOn);
if (o.sarif) {
  const s = JSON.stringify(toSarif(result, { version: VERSION }), null, 2);
  if (o.sarifFile) { writeFileSync(o.sarifFile, s); if (!o.json) console.log(pretty(result, { showInfo: o.info })); } else console.log(s);
}
if (o.json) {
  const { baselineCandidates, gitleaksErrors, ...pub } = result;
  console.log(JSON.stringify({ failOn, failed, ...pub }, null, 2));
} else if (!o.sarif) console.log(pretty(result, { showInfo: o.info }));
process.exitCode = failed ? 1 : 0;
