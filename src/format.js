const useColor = (stream) => !('NO_COLOR' in process.env) && (process.env.FORCE_COLOR || stream?.isTTY);
export function pretty(result, { color = useColor(process.stdout), showInfo = true } = {}) {
  const c = (code) => (s) => color ? `\x1b[${code}m${s}\x1b[0m` : String(s);
  const red = c(31), yellow = c(33), green = c(32), dim = c(2), bold = c(1), cyan = c(36);
  const lines = [];
  const findings = result.findings.filter((f) => showInfo || f.severity !== 'info');
  const byFile = new Map();
  for (const f of findings) { const k = f.file; if (!byFile.has(k)) byFile.set(k, []); byFile.get(k).push(f); }
  if (!findings.length) lines.push('', green(`✔ no secrets found in ${result.files.length} file(s)`) + dim(` (${result.dirs.join(', ')})`));
  for (const [file, fs] of byFile) {
    lines.push('', bold(file));
    for (const f of fs) {
      const tag = f.severity === 'error' ? red('✖ error') : f.severity === 'warn' ? yellow('⚠ warn ') : dim('ℹ info ');
      const where = `${f.file}${f.source ? ` (${f.source})` : ''}:${f.line}:${f.column}`;
      lines.push(`  ${tag} ${bold(f.title)} ${dim('[' + f.id + ']')}`, `          ${where}${f.match ? '  ' + dim(f.match) : ''}`);
      if (f.message) lines.push(`          ${f.message}`);
      if (f.fix) lines.push(...f.fix.split('\n').map((l, i) => `          ${i ? '  ' : cyan('fix: ')}${dim(l)}`));
    }
  }
  for (const s of result.skipped || []) lines.push(dim(`  skipped ${s.file} (${s.size} bytes > --max-file-size)`));
  const e = findings.filter((f) => f.severity === 'error').length;
  const w = findings.filter((f) => f.severity === 'warn').length;
  lines.push('', `${result.files.length} file(s) scanned: ${e ? red(e + ' error(s)') : green('0 errors')}, ${w ? yellow(w + ' warning(s)') : '0 warnings'}`);
  return lines.join('\n');
}
