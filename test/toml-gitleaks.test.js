import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseToml } from '../src/toml.js';
import { loadGitleaksRules } from '../src/gitleaks.js';
import { scan } from '../src/scan.js';

test('parseToml handles gitleaks-style rules', () => {
  const doc = parseToml(`
title = "test"
[[rules]]
id = "acme-key"
description = "ACME key"
regex = '''(?i)acme[_-]?key\\s*=\\s*["']?([a-f0-9]{32})["']?'''
secretGroup = 1
entropy = 3.0
keywords = ["acme"]
`);
  assert.equal(doc.title, 'test');
  assert.equal(doc.rules.length, 1);
  assert.equal(doc.rules[0].id, 'acme-key');
  assert.equal(doc.rules[0].secretGroup, 1);
});

test('loadGitleaksRules and scan custom gitleaks rule', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bsg-gl-'));
  writeFileSync(join(dir, 'custom.toml'), `[[rules]]
id = "acme-key"
description = "ACME internal"
regex = '''ACME-SECRET-([A-F0-9]{16})'''
secretGroup = 1
`);
  mkdirSync(join(dir, 'dist'), { recursive: true });
  writeFileSync(join(dir, 'dist/a.js'), 'const x = "ACME-SECRET-0123456789ABCDEF";');
  const { rules, errors } = loadGitleaksRules(['custom.toml'], dir);
  assert.equal(errors.length, 0);
  assert.equal(rules.length, 1);
  const r = scan(['dist'], { cwd: dir, gitleaks: ['custom.toml'] });
  assert.ok(r.findings.some((f) => f.id === 'gitleaks:acme-key'));
  rmSync(dir, { recursive: true });
});
