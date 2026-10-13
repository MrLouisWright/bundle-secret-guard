import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
export const CONFIG_FILES = ['.envleakrc.json', '.bundlesecretguardrc.json', 'bundle-secret-guard.config.json'];
export function loadConfig(file, cwd = process.cwd()) {
  const f = file || CONFIG_FILES.find((n) => existsSync(resolve(cwd, n)));
  if (!f) return {};
  return JSON.parse(readFileSync(resolve(cwd, f), 'utf8'));
}
