/** Reusable secret patterns for bundle-secret-guard and sibling sentinel packages. */
import { RULES, FILE_RULES, entropy, redact } from './rules.js';
export { RULES, FILE_RULES, entropy, redact };
export { loadGitleaksRules, lineMatchesKeywords, isGitleaksAllowed } from './gitleaks.js';

/** Built-in rule metadata without RegExp instances (for docs / tooling). */
export function listBuiltinPatterns() {
  return RULES.map(({ id, title, severity, entropy: ent, fix }) => ({ id, title, severity, entropy: ent, fix }));
}
