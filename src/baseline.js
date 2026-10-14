import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const BASELINE_VERSION = '1.0';

/** Stable hash for a secret (never written to baseline in plaintext). */
export function hashSecret(secret, id = '') {
  return createHash('sha256').update(`${id}\0${secret}`).digest('hex');
}

function normalizeEntry(e) {
  return {
    id: e.id,
    file: e.file,
    line: e.line,
    column: e.column ?? 1,
    hash: e.hash,
    source: e.source,
  };
}

/**
 * Load baseline from detect-secrets JSON or bundle-secret-guard format.
 * @returns {{ version: string, entries: object[], raw: object }}
 */
export function loadBaseline(file, cwd = process.cwd()) {
  if (!file) return { version: BASELINE_VERSION, entries: [], raw: { version: BASELINE_VERSION, findings: [] } };
  const abs = resolve(cwd, file);
  if (!existsSync(abs)) return { version: BASELINE_VERSION, entries: [], raw: { version: BASELINE_VERSION, findings: [] }, missing: true };
  const raw = JSON.parse(readFileSync(abs, 'utf8'));
  const entries = [];
  if (raw.results && typeof raw.results === 'object' && !Array.isArray(raw.results)) {
    for (const [filePath, items] of Object.entries(raw.results)) {
      for (const it of items) {
        entries.push(normalizeEntry({
          id: it.type || it.id || 'unknown',
          file: it.filename || filePath,
          line: it.line_number ?? it.line ?? 1,
          column: it.column ?? 1,
          hash: it.hashed_secret || it.hash,
          source: it.source,
        }));
      }
    }
  } else {
    for (const it of raw.findings || raw.entries || []) {
      entries.push(normalizeEntry(it));
    }
  }
  return { version: raw.version || BASELINE_VERSION, entries, raw, path: abs };
}

/** Whether a finding is suppressed by the baseline (hash match; file must match). */
export function isBaselined(finding, secret, baseline) {
  const h = hashSecret(secret, finding.id);
  return baseline.entries.some((e) => e.hash === h && e.file === finding.file && (e.id === finding.id || !e.id || e.id === 'unknown'));
}

/** Merge scan findings into baseline (stores hashes only). */
export function updateBaseline(raw, findingsWithSecrets) {
  const findings = [...(raw.findings || raw.entries || [])];
  const seen = new Set(findings.map((f) => `${f.hash}|${f.file}|${f.id}`));
  for (const { finding, secret } of findingsWithSecrets) {
    const entry = {
      id: finding.id,
      file: finding.file,
      line: finding.line,
      column: finding.column,
      hash: hashSecret(secret, finding.id),
      source: finding.source,
    };
    const key = `${entry.hash}|${entry.file}|${entry.id}`;
    if (!seen.has(key)) {
      findings.push(entry);
      seen.add(key);
    }
  }
  return { version: raw.version || BASELINE_VERSION, generatedAt: new Date().toISOString(), findings };
}

export function writeBaseline(file, data, cwd = process.cwd()) {
  writeFileSync(resolve(cwd, file), `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}

export { BASELINE_VERSION };
