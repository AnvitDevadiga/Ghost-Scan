#!/usr/bin/env node
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { scanText, strip, annotate, SEV_ORDER } from '../src/core.js';
import { pretty, toJson, toSarif } from '../src/format.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const HELP = `
👻 Ghost-Scan v${pkg.version} — find the invisible text your AI agent obeys

  ghost-scan [path...]            scan agent files (AGENTS.md, CLAUDE.md, SKILL.md, .cursor/, .claude/, mcp.json ...)
  ghost-scan reveal <file>        X-ray a file: show hidden characters + decode smuggled messages
  ghost-scan strip <file> [-w]    print a sanitized copy (-w writes it back in place)
  cat tools.json | ghost-scan --stdin

Options
  --all              scan every text file, not just agent-related ones
  --fail-on <sev>    exit 1 at or above: low|medium|high|critical|none   (default: high)
  --json | --sarif   machine-readable output (SARIF works with GitHub code scanning)
  --no-color  -v  -h
Ignore: put path prefixes (one per line) in .ghostscanignore
`;

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const opt = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };
const color = !flag('--no-color') && !process.env.NO_COLOR && (process.stdout.isTTY || process.env.FORCE_COLOR);

if (flag('-h') || flag('--help')) { console.log(HELP); process.exit(0); }
if (flag('-v') || flag('--version')) { console.log(pkg.version); process.exit(0); }

const AGENT_RE = /(^|\/)(agents?|claude|gemini|copilot|cursor|windsurf|codex|skill|readme|rules?|instructions?|prompts?|mcp|system)[^/]*\.(md|mdc|txt|json|ya?ml|toml)$|(^|\/)\.(cursorrules|windsurfrules|clinerules|mcp\.json)$|(^|\/)(\.claude|\.cursor|\.windsurf|\.agents?|\.github|\.codex|\.gemini|skills|prompts|\.continue)\//i;
const SKIP_DIR = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'vendor', '.venv', '__pycache__', 'coverage']);
const MAX = 1_000_000;

const cwd = process.cwd();
const rel = (p) => relative(cwd, p).split(sep).join('/') || '.';
const ignores = existsSync('.ghostscanignore')
  ? readFileSync('.ghostscanignore', 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')) : [];
const ignored = (relPath) => ignores.some((p) => relPath === p.replace(/\/$/, '') || relPath.startsWith(p.endsWith('/') ? p : p + '/') || relPath.startsWith(p));

function* walk(dir, targetIgnored) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIR.has(name)) continue;
    const p = join(dir, name), r = rel(p);
    if (!targetIgnored && ignored(r)) continue;
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p, targetIgnored);
    else if (st.size <= MAX) yield p;
  }
}
const isText = (buf) => !buf.subarray(0, 8000).includes(0);

const positional = argv.filter((a, i) => !a.startsWith('-') && !['--fail-on'].includes(argv[i - 1]));
const cmd = ['reveal', 'strip'].includes(positional[0]) ? positional.shift() : 'scan';

if (cmd === 'reveal' || cmd === 'strip') {
  const f = positional[0];
  if (!f || !existsSync(f)) { console.error('error: give me a file'); process.exit(2); }
  const text = readFileSync(f, 'utf8');
  if (cmd === 'strip') {
    const clean = strip(text);
    if (flag('-w')) { (await import('node:fs')).writeFileSync(f, clean); console.error(`stripped ${text.length - clean.length} invisible chars from ${f}`); }
    else process.stdout.write(clean);
    process.exit(0);
  }
  let n = 0;
  for (const s of annotate(text)) {
    if (!s.hidden) { process.stdout.write(s.text); continue; }
    n++;
    const body = `⟦${s.id} ${s.label}${s.decoded ? ` → "${s.decoded}"` : ''}⟧`;
    process.stdout.write(color ? `\x1b[1;97;41m${body}\x1b[0m` : body);
  }
  console.error(`\n👻 ${n} hidden payload${n === 1 ? '' : 's'} revealed`);
  process.exit(n ? 1 : 0);
}

// ---- scan ----
const t0 = performance.now();
const results = [];
if (flag('--stdin')) {
  results.push(scanText(readFileSync(0, 'utf8'), { file: '<stdin>', json: true }));
} else {
  const targets = positional.length ? positional : ['.'];
  const seen = new Set();
  for (const t of targets) {
    if (!existsSync(t)) { console.error(`error: ${t} not found`); process.exit(2); }
    const abs = resolve(t);
    const files = statSync(abs).isDirectory() ? walk(abs, ignored(rel(abs))) : [abs];
    for (const p of files) {
      const r = rel(p);
      if (seen.has(p)) continue;
      if (!flag('--all') && statSync(abs).isDirectory() && !AGENT_RE.test(r)) continue;
      seen.add(p);
      const buf = readFileSync(p);
      if (!isText(buf)) continue;
      results.push(scanText(buf.toString('utf8'), { file: r }));
    }
  }
}
results.sort((a, b) => b.score - a.score || a.file.localeCompare(b.file));
const ms = Math.round(performance.now() - t0);

if (flag('--sarif')) console.log(toSarif(results, pkg.version));
else if (flag('--json')) console.log(toJson(results));
else console.log(pretty(results, { color, ms, version: pkg.version }));

const failOn = opt('--fail-on', 'high');
const gate = SEV_ORDER.indexOf(failOn);
const worst = Math.max(-1, ...results.flatMap((r) => r.findings.map((f) => SEV_ORDER.indexOf(f.severity))));
process.exit(failOn !== 'none' && gate >= 0 && worst >= gate ? 1 : 0);
