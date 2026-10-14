import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { parseToml } from './toml.js';

function normalizeAllowlist(a) {
  if (!a || typeof a !== 'object') return null;
  return {
    regexes: (a.regexes || a.Regexes || []).map(String),
    paths: (a.paths || a.Paths || []).map(String),
    stopwords: (a.stopwords || a.Stopwords || []).map(String),
    regexTarget: a.regexTarget || a.RegexTarget || 'match',
  };
}

function parseRule(vr, file) {
  if (!vr.id || !vr.regex) return null;
  let re;
  try {
    re = new RegExp(vr.regex, 'g');
  } catch (e) {
    return { error: `${vr.id}: invalid regex (${e.message})`, file };
  }
  const allowlists = [];
  if (vr.allowlist) allowlists.push(normalizeAllowlist(vr.allowlist));
  for (const a of vr.allowlists || vr.Allowlists || []) {
    const n = normalizeAllowlist(a);
    if (n) allowlists.push(n);
  }
  return {
    id: `gitleaks:${vr.id}`,
    title: vr.description || vr.id,
    severity: 'error',
    re,
    group: vr.secretGroup ?? vr.secretgroup ?? 0,
    entropy: vr.entropy,
    keywords: (vr.keywords || []).map((k) => String(k).toLowerCase()),
    path: vr.path ? new RegExp(vr.path) : null,
    allowlists,
    fix: `Remove this secret from client code (gitleaks rule ${vr.id}). Rotate if it was deployed.`,
    skipReport: !!vr.skipReport,
    source: file,
  };
}

function mergeRules(base, extra) {
  const byId = new Map(base.map((r) => [r.id.replace(/^gitleaks:/, ''), r]));
  for (const r of extra) {
    const key = r.id.replace(/^gitleaks:/, '');
    byId.set(key, r);
  }
  return [...byId.values()];
}

function loadTomlFile(abs, cwd) {
  const text = readFileSync(abs, 'utf8');
  const doc = parseToml(text);
  const rules = [];
  const errors = [];
  for (const vr of doc.rules || []) {
    const r = parseRule(vr, abs);
    if (!r) continue;
    if (r.error) errors.push(r.error);
    else if (!r.skipReport) rules.push(r);
  }
  const globalAllow = [];
  for (const a of [...(doc.allowlists || []), doc.allowlist].filter(Boolean)) {
    const n = normalizeAllowlist(a);
    if (n) globalAllow.push(n);
  }
  let extendRules = [];
  const ext = doc.extend;
  if (ext?.path) {
    const p = resolve(dirname(abs), ext.path);
    if (existsSync(p)) {
      const sub = loadTomlFile(p, cwd);
      extendRules = sub.rules;
      errors.push(...sub.errors);
    } else errors.push(`extend.path not found: ${ext.path}`);
  }
  if (ext?.useDefault) {
    errors.push('extend.useDefault is not bundled; point gitleaks config at config/gitleaks.toml from the gitleaks repo or use extend.path');
  }
  return { rules: mergeRules(extendRules, rules), globalAllow, errors, doc };
}

/**
 * Load gitleaks-style TOML rule files into scan-compatible rules and allowlist hints.
 * @param {string|string[]} paths
 * @param {string} [cwd]
 */
export function loadGitleaksRules(paths, cwd = process.cwd()) {
  const list = Array.isArray(paths) ? paths : [paths];
  const allRules = [];
  const globalAllow = [];
  const errors = [];
  for (const rel of list) {
    const abs = resolve(cwd, rel);
    if (!existsSync(abs)) {
      errors.push(`gitleaks config not found: ${rel}`);
      continue;
    }
    const { rules, globalAllow: ga, errors: e } = loadTomlFile(abs, cwd);
    allRules.push(...rules);
    globalAllow.push(...ga);
    errors.push(...e);
  }
  return { rules: allRules, globalAllow, errors };
}

/** True if gitleaks keyword pre-filter passes for this line (empty keywords = always). */
export function lineMatchesKeywords(line, keywords) {
  if (!keywords?.length) return true;
  const lower = line.toLowerCase();
  return keywords.some((k) => lower.includes(k));
}

/** Apply gitleaks rule-level allowlists to a secret or match string. */
export function isGitleaksAllowed(secret, match, allowlists) {
  for (const a of allowlists || []) {
    for (const rx of a.regexes || []) {
      try {
        const target = a.regexTarget === 'line' ? match : secret;
        if (new RegExp(rx).test(target)) return true;
      } catch { /* skip bad regex */ }
    }
    for (const w of a.stopwords || []) {
      if (secret === w || match.includes(w)) return true;
    }
  }
  return false;
}
