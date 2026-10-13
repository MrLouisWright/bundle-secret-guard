export function toSarif(result, { version = '1.0.0' } = {}) {
  const rules = new Map();
  for (const f of result.findings) if (!rules.has(f.id)) rules.set(f.id, { id: f.id, name: f.id, shortDescription: { text: f.title }, help: { text: f.fix || f.title } });
  const level = { error: 'error', warn: 'warning', info: 'note' };
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'bundle-secret-guard', version, informationUri: 'https://github.com/MrLouisWright/bundle-secret-guard', rules: [...rules.values()] } },
      results: result.findings.map((f) => ({
        ruleId: f.id, level: level[f.severity] || 'note',
        message: { text: `${f.title}${f.match ? ` (${f.match})` : ''}${f.source ? ` in ${f.source}` : ''}${f.message ? ': ' + f.message : ''}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line, startColumn: f.column } } }],
      })),
    }],
  };
}
