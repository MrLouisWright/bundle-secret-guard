import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { scan } from '../src/scan.js';
import { hashSecret, loadBaseline, updateBaseline, writeBaseline, isBaselined } from '../src/baseline.js';
import { RULES, listBuiltinPatterns } from '../src/patterns.js';
import { FAKE } from './fake-keys.js';

test('baseline suppresses known findings by hash', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bsg-bl-'));
  mkdirSync(join(dir, 'dist'), { recursive: true });
  writeFileSync(join(dir, 'dist/a.js'), `x="${FAKE.github}"`);
  const h = hashSecret(FAKE.github, 'github-token');
  writeFileSync(join(dir, 'baseline.json'), JSON.stringify({
    version: '1.0',
    findings: [{ id: 'github-token', file: 'dist/a.js', line: 1, column: 1, hash: h }],
  }));
  const r = scan(['dist'], { cwd: dir, baseline: 'baseline.json' });
  assert.equal(r.findings.length, 0);
  rmSync(dir, { recursive: true });
});

test('updateBaseline stores hashes only', () => {
  const finding = { id: 'github-token', file: 'dist/a.js', line: 1, column: 1 };
  const data = updateBaseline({ version: '1.0', findings: [] }, [{ finding, secret: FAKE.github }]);
  assert.ok(data.findings[0].hash);
  assert.equal(data.findings[0].hash, hashSecret(FAKE.github, 'github-token'));
  assert.equal(isBaselined(finding, FAKE.github, loadBaseline(null)), false);
});

test('entropy-scan finds high-entropy quoted string', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bsg-ent-'));
  mkdirSync(join(dir, 'dist'), { recursive: true });
  const token = 'Zx9+kL3mN8pQ2rT5vW7yA1bC4dE6fG8h';
  writeFileSync(join(dir, 'dist/a.js'), `const cfg = "${token}";`);
  const r = scan(['dist'], { cwd: dir, entropyScan: true, config: { rules: { 'generic-secret': 'off' } } });
  assert.ok(r.findings.some((f) => f.id === 'entropy-string'));
  rmSync(dir, { recursive: true });
});

test('patterns entry exports RULES and listBuiltinPatterns', () => {
  assert.ok(RULES.length > 10);
  assert.ok(listBuiltinPatterns().every((p) => p.id && p.title));
});

test('require and import resolve built package exports', () => {
  const require = createRequire(import.meta.url);
  const cjs = require('../dist/index.cjs');
  assert.equal(typeof cjs.scan, 'function');
  assert.equal(typeof cjs.loadGitleaksRules, 'function');
  const patterns = require('../dist/patterns.cjs');
  assert.ok(patterns.RULES.length > 0);
});

test('ESM import of dist entry points', async () => {
  const main = await import('../dist/index.js');
  const patterns = await import('../dist/patterns.js');
  assert.equal(typeof main.scan, 'function');
  assert.equal(typeof patterns.listBuiltinPatterns, 'function');
});
