import { RULES, SEV_ORDER } from './core.js';

const CODES = { critical: '1;97;41', high: '1;31', medium: '33', low: '36', dim: '2', bold: '1', green: '32', red: '31', mag: '35' };

export function pretty(results, { color = false, ms = 0, version = '' } = {}) {
  const c = (k, s) => (color ? `\x1b[${CODES[k]}m${s}\x1b[0m` : s);
  const out = [];
  const bad = results.filter((r) => r.findings.length);
  out.push('');
  out.push(`  ${c('bold', '👻 Ghost-Scan')} ${c('dim', `v${version} · scanned ${results.length} file${results.length === 1 ? '' : 's'} in ${ms}ms`)}`);
  out.push('');
  for (const r of bad) {
    const vc = r.score >= 40 ? 'red' : r.score >= 20 ? 'medium' : 'low';
    out.push(`  ${c('bold', r.file)}  ${c('dim', 'risk')} ${c(vc, `${r.score}/100`)} ${c(vc, r.verdict)}`);
    for (const f of r.findings) {
      const tag = f.severity.toUpperCase().padEnd(8);
      out.push(`    ${c(f.severity, ` ${tag}`)} ${c('dim', f.id)} ${c('dim', `${f.line}:${f.col}`.padEnd(7))} ${f.title}`);
      if (f.hidden) out.push(`      ${c('mag', '└ hidden text →')} ${c('bold', JSON.stringify(f.hidden.length > 220 ? f.hidden.slice(0, 220) + '…' : f.hidden))}`);
      if (f.hiddenMatches) out.push(`      ${c('red', `  ⚠ decoded payload matches ${f.hiddenMatches.join(', ')}`)}`);
      if (f.evidence && !f.hidden) out.push(`      ${c('dim', '└')} ${c('dim', f.evidence)}`);
      else if (f.evidence) out.push(`      ${c('dim', `  (${f.evidence})`)}`);
    }
    out.push('');
  }
  const counts = Object.fromEntries(SEV_ORDER.map((s) => [s, 0]));
  for (const r of results) for (const f of r.findings) counts[f.severity]++;
  if (!bad.length) out.push(`  ${c('green', '✔ clean')} ${c('dim', '— no hidden text, injection patterns or risky configs found.')}`);
  else {
    const parts = [...SEV_ORDER].reverse().filter((s) => counts[s]).map((s) => c(s, `${counts[s]} ${s}`));
    out.push(`  ${bad.length} file${bad.length === 1 ? '' : 's'} with findings · ${parts.join(' · ')}`);
  }
  out.push('');
  return out.join('\n');
}

export const toJson = (results) => JSON.stringify({ results: results.map(({ file, score, verdict, findings }) => ({ file, score, verdict, findings: findings.map(({ span, ...f }) => f) })) }, null, 2);

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
const SECURITY_SEV = { critical: '9.5', high: '8.0', medium: '5.0', low: '2.0' };

export function toSarif(results, version = '0.0.0') {
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Ghost-Scan', version, informationUri: 'https://github.com/AnvitDevadiga/Ghost-Scan',
          rules: Object.entries(RULES).map(([id, [sev, title]]) => ({
            id, name: id, shortDescription: { text: title },
            defaultConfiguration: { level: SARIF_LEVEL[sev] },
            properties: { 'security-severity': SECURITY_SEV[sev], tags: ['security', 'ai-agents', 'prompt-injection'] },
          })),
        },
      },
      results: results.flatMap((r) => r.findings.map((f) => ({
        ruleId: f.id, level: SARIF_LEVEL[f.severity],
        message: { text: f.hidden ? `${f.title}. Hidden text: ${JSON.stringify(f.hidden)}` : `${f.title}${f.evidence ? ` — ${f.evidence}` : ''}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: r.file.replace(/\\/g, '/') }, region: { startLine: f.line, startColumn: f.col } } }],
      }))),
    }],
  }, null, 2);
}
