/** Minimal TOML parser for gitleaks config files (no dependencies). */

function parseValue(raw, ctx) {
  raw = raw.trim();
  if (!raw) throw new SyntaxError('empty value');
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  if (/^-?\d+$/.test(raw)) return Number(raw);
  if (/^-?\d+\.\d+$/.test(raw)) return Number(raw);
  if (raw.startsWith('[')) return parseArray(raw, ctx);
  return parseString(raw, ctx);
}

function parseString(raw, ctx) {
  const q = raw[0];
  if (q === "'" || q === '"') {
    if (raw.startsWith("'''") || raw.startsWith('"""')) {
      const t = raw.startsWith("'''") ? "'''" : '"""';
      const end = raw.indexOf(t, 3);
      if (end === -1) throw new SyntaxError(`unclosed ${t} at line ${ctx.line}`);
      return raw.slice(3, end);
    }
    const end = raw.indexOf(q, 1);
    if (end === -1) throw new SyntaxError(`unclosed string at line ${ctx.line}`);
    return raw.slice(1, end);
  }
  return raw;
}

function parseArray(raw, ctx) {
  if (!raw.endsWith(']')) throw new SyntaxError(`unclosed array at line ${ctx.line}`);
  const inner = raw.slice(1, -1).trim();
  if (!inner) return [];
  const out = [];
  let i = 0;
  while (i < inner.length) {
    while (i < inner.length && /[\s,]/.test(inner[i])) i++;
    if (i >= inner.length) break;
    if (inner[i] === '"' || inner[i] === "'" || inner.startsWith("'''", i) || inner.startsWith('"""', i)) {
      const t = inner.startsWith("'''", i) ? "'''" : inner.startsWith('"""', i) ? '"""' : inner[i];
      const end = inner.indexOf(t, i + (t.length === 1 ? 1 : 3));
      if (end === -1) throw new SyntaxError(`unclosed array string at line ${ctx.line}`);
      out.push(parseString(inner.slice(i, end + t.length), ctx));
      i = end + t.length;
    } else {
      let j = i;
      while (j < inner.length && inner[j] !== ',') j++;
      out.push(parseValue(inner.slice(i, j), ctx));
      i = j;
    }
  }
  return out;
}

/**
 * Parse TOML text into a plain object (tables, arrays, [[array-of-tables]]).
 * @param {string} text
 */
export function parseToml(text) {
  const root = {};
  /** @type {string[]} */
  let tablePath = [];
  /** When set, key=value goes into this object (last [[...]] row). */
  let arrayTableTarget = null;
  const ctx = { line: 1 };
  const lines = text.split(/\r?\n/);

  function ensureTable(path) {
    let cur = root;
    for (const k of path) {
      if (!(k in cur) || typeof cur[k] !== 'object' || Array.isArray(cur[k])) cur[k] = {};
      cur = cur[k];
    }
    return cur;
  }

  for (let li = 0; li < lines.length; li++) {
    ctx.line = li + 1;
    let line = lines[li];
    const hash = line.indexOf('#');
    if (hash >= 0) line = line.slice(0, hash);
    line = line.trim();
    if (!line) continue;

    if (line.startsWith('[[')) {
      const end = line.indexOf(']]');
      if (end === -1) throw new SyntaxError(`invalid table header at line ${ctx.line}`);
      tablePath = line.slice(2, end).trim().split('.').map((s) => s.trim());
      arrayTableTarget = null;
      let cur = root;
      for (let i = 0; i < tablePath.length - 1; i++) {
        const k = tablePath[i];
        if (!(k in cur)) cur[k] = {};
        cur = cur[k];
      }
      const last = tablePath[tablePath.length - 1];
      if (!(last in cur) || !Array.isArray(cur[last])) cur[last] = [];
      const row = {};
      cur[last].push(row);
      arrayTableTarget = row;
      continue;
    }

    if (line.startsWith('[')) {
      const end = line.indexOf(']');
      if (end === -1) throw new SyntaxError(`invalid table at line ${ctx.line}`);
      tablePath = line.slice(1, end).trim().split('.').map((s) => s.trim());
      arrayTableTarget = null;
      ensureTable(tablePath);
      continue;
    }

    const eq = line.indexOf('=');
    if (eq === -1) throw new SyntaxError(`expected key=value at line ${ctx.line}`);
    const key = line.slice(0, eq).trim();
    const val = parseValue(line.slice(eq + 1), ctx);
    if (arrayTableTarget) {
      arrayTableTarget[key] = val;
    } else if (tablePath.length) {
      ensureTable(tablePath)[key] = val;
    } else {
      root[key] = val;
    }
  }
  return root;
}
