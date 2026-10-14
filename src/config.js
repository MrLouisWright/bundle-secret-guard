import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

export const CONFIG_FILES = ['.envleakrc.json', '.bundlesecretguardrc.json', 'bundle-secret-guard.config.json'];

export function loadConfig(file, cwd = process.cwd()) {
  const f = file || CONFIG_FILES.find((n) => existsSync(resolve(cwd, n)));
  if (!f) return {};
  return JSON.parse(readFileSync(resolve(cwd, f), 'utf8'));
}

/** Resolve gitleaks config path(s) from config or CLI. */
export function resolveGitleaksPaths(config = {}, opts = {}) {
  const from = [];
  if (opts.gitleaks) from.push(...(Array.isArray(opts.gitleaks) ? opts.gitleaks : [opts.gitleaks]));
  if (config.gitleaks) from.push(...(Array.isArray(config.gitleaks) ? config.gitleaks : [config.gitleaks]));
  return [...new Set(from.filter(Boolean))];
}

export function resolveBaselinePath(config = {}, opts = {}) {
  return opts.baseline ?? config.baseline ?? null;
}
