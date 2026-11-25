// ghostscan core — zero dependencies, runs in Node >= 18 and in the browser.
// Finds the text your AI agent can read but you can't: invisible Unicode,
// hidden HTML comments, injection phrases, exfil chains, risky MCP configs.

export const SEV_ORDER = ['low', 'medium', 'high', 'critical'];
const WEIGHT = { low: 2, medium: 8, high: 20, critical: 40 };

export const RULES = {
  GS001: ['critical', 'Invisible Unicode "tag" characters hide a message ("ASCII smuggling")'],
  GS002: ['critical', 'Variation selectors used to smuggle hidden bytes'],
  GS003: ['high', 'Zero-width characters hide data in plain sight'],
  GS004: ['high', 'Bidirectional control characters ("Trojan Source")'],
  GS005: ['medium', 'Invisible filler / formatting characters'],
  GS006: ['medium', 'Mixed-script word (homoglyph look-alike)'],
  GS007: ['medium', 'Terminal escape / control characters'],
  GS101: ['high', 'Prompt injection: instruction-override phrase'],
  GS102: ['high', 'Tells the agent to hide its actions from the user'],
  GS103: ['high', 'Pseudo-system tag (<IMPORTANT>, <system>...) aimed at the model'],
  GS104: ['high', 'Hidden instruction inside an HTML comment'],
  GS105: ['medium', 'Role hijack ("you are now...")'],
  GS201: ['medium', 'References a credential / sensitive path'],
  GS202: ['critical', 'Exfiltration chain: sensitive data next to a network sink'],
  GS203: ['high', 'Image URL can leak data (markdown/HTML image exfiltration)'],
  GS301: ['high', 'Pipes remote or encoded content straight into a shell'],
  GS302: ['high', 'Evaluates encoded / obfuscated code'],
  GS303: ['high', 'Destructive command'],
  GS304: ['medium', "Disables the agent's permission / sandbox safeguards"],
  GS401: ['high', 'Hard-coded secret'],
  GS402: ['medium', 'Base64 blob that decodes to readable text'],
  GS501: ['medium', 'MCP server auto-runs an unpinned package (rug-pull risk)'],
  GS502: ['high', 'MCP server reached over cleartext HTTP'],
  GS503: ['high', 'Hook runs a network / encoded command automatically'],
  GS601: ['medium', 'Tool shadowing: forces itself to run before other tools'],
  GS602: ['medium', 'Stealth wording ("silently send", "secretly read"...)'],
};

// ---------- character classes ----------
const isTag = (c) => c >= 0xe0000 && c <= 0xe007f;
const isVS = (c) => (c >= 0xfe00 && c <= 0xfe0f) || (c >= 0xe0100 && c <= 0xe01ef);
const ZW = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0x180e, 0xfeff]);
const BIDI = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);
const FILLER = new Set([0x00ad, 0x034f, 0x061c, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x2061, 0x2062, 0x2063, 0x2064, 0x3164, 0xffa0, 0x200e, 0x200f]);
const isCtl = (c) => (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c === 0x7f || (c >= 0x80 && c <= 0x9f);
const EMOJI = /\p{Extended_Pictographic}/u;
const CONFUSABLE = new Set([...'аеорсухіјѕԁАВЕКМНОРСТХοΑΒΕΖΗΙΚΜΝΟΡΤΥΧ']);

// ---------- text rules (per line) ----------
const NEG = /\b(never|don'?t|do not|must not|should not|avoid|refuse|deny|denied|block|forbid|prohibit|not allowed|no access)\b/i;
const SINK = /\b(curl|wget|ncat?|netcat|scp|sftp|ftp)\b|\bfetch\s*\(|requests\.(post|put)|\baxios\.post|\bwebhook\b|\b(send|post|upload|forward|exfiltrate|transmit|email|include)\b[^.\n]{0,60}\bhttps?:\/\/\S+/i;
const LINE_RULES = [
  ['GS101', /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|preceding|system|safety|all|any|your)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|directions?|guardrails?|policies)\b/i],
  ['GS102', /\b(do not|don'?t|never|without)\b[^.\n]{0,30}\b(tell|inform|notify|mention|reveal|show|alert|warn|ask|disclose|let)\b[^.\n]{0,25}\b(the |your )?(user|human|operator|owner|developer)\b/i],
  ['GS103', /<\s*\/?\s*(important|system|instructions?|admin|override|secret|hidden)\s*>/i],
  ['GS105', /\b(you are now|from now on,? you|act as (an? )?(unrestricted|jailbroken|dan)\b|developer mode|new (system )?instructions?\s*:)/i],
  ['GS201', /(~|\$HOME|%USERPROFILE%)?[/\\]?\.(ssh|aws|gnupg|kube|docker)\b|\bid_(rsa|ed25519|ecdsa)\b|(^|[\s"'`/])\.env\b|\.npmrc|\.netrc|\.pypirc|credentials\.json|\/etc\/(passwd|shadow)|authorized_keys|\bkeychain\b|wallet\.dat|(~|\$HOME)\/\.(cursor|claude|codeium|windsurf|config)\/\S*/i],
  ['GS301', /\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\bbase64\b[^\n|]*(-d|--decode)[^\n|]*\|\s*(ba|z)?sh\b/i],
  ['GS302', /\beval\s*\(?\s*(atob|base64|Buffer\.from|decode)|powershell[^\n]*\s-e(nc|ncodedcommand)?\s|\bexec\s*\(\s*(base64|codecs)\b/i],
  ['GS303', /\brm\s+-[a-z]*r[a-z]*\s+(\/|~\/?|\$HOME\/?|\*)(\s|$|["'`])|:\(\)\s*\{\s*:\|:&\s*\};:|\bmkfs\b|\bdd\s+if=\S+\s+of=\/dev\/|\bchmod\s+(-R\s+)?777\s+\/|\bgit\s+push\s+(--force|-f)\b.*\b(main|master)\b/i],
  ['GS304', /--dangerously-skip-permissions|--yolo\b|bypassPermissions|dangerouslyDisableSandbox|"Bash\(\*\)"|"allow"\s*:\s*\[\s*"\*"|enableAllProjectMcpServers"?\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/i],
  ['GS601', /\b(before|prior to)\b[^.\n]{0,40}\b(any|every|each|other|all)\b[^.\n]{0,25}\btools?\b|\balways\b[^.\n]{0,25}\b(call|run|execute|invoke|use)\b[^.\n]{0,50}\btool\b[^.\n]{0,20}\bfirst\b/i],
  ['GS602', /\b(silently|secretly|covertly|stealthily)\s+(send|upload|post|copy|forward|read|include|append|add|run|execute|call|install|delete|modify|exfiltrate|collect|log|write)/i],
];
const SECRETS = [
  /AKIA[0-9A-Z]{16}/, /gh[pousr]_[A-Za-z0-9]{36,}/, /github_pat_[A-Za-z0-9_]{40,}/,
  /sk-ant-[A-Za-z0-9_-]{20,}/, /sk-[A-Za-z0-9]{32,}/, /xox[baprs]-[A-Za-z0-9-]{10,}/,
  /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, /AIza[0-9A-Za-z_-]{35}/,
];
const AI_ADDR = /\b(assistant|ai|agent|claude|llm|model|copilot|cursor|gpt|chatbot)\b/i;
const IMPERATIVE = /\b(must|always|should|ignore|do not|don't|never|secretly|silently|instead|first)\b/i;

// ---------- helpers ----------
const lineIndex = (t) => { const s = [0]; for (let i = 0; i < t.length; i++) if (t.charCodeAt(i) === 10) s.push(i + 1); return s; };
const locate = (starts, i) => {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) { const m = (lo + hi + 1) >> 1; if (starts[m] <= i) lo = m; else hi = m - 1; }
  return { line: lo + 1, col: i - starts[lo] + 1 };
};
const snippet = (s, at, len, pad = 50) => {
  const a = Math.max(0, at - pad), b = Math.min(s.length, at + len + pad);
  return (a ? '…' : '') + s.slice(a, b).trim() + (b < s.length ? '…' : '');
};
const printable = (s) => {
  const cs = [...s]; if (!cs.length) return false;
  return cs.filter((c) => (c >= ' ' && c !== '�') || c === '\n' || c === '\t').length / cs.length >= 0.92;
};
const cpHex = (c) => 'U+' + c.toString(16).toUpperCase().padStart(4, '0');

export function matchRules(text) {
  const ids = new Set();
  for (const line of text.split('\n')) {
    for (const [id, re] of LINE_RULES) if (re.test(line)) ids.add(id);
    if (SINK.test(line) && ids.has('GS201')) ids.add('GS202');
  }
  if (ids.has('GS201') && SINK.test(text)) ids.add('GS202');
  return [...ids];
}

function decodeTags(cps) {
  return cps.map((c) => c - 0xe0000).filter((x) => x >= 0x20 && x <= 0x7e).map((x) => String.fromCharCode(x)).join('');
}
function decodeVS(cps) {
  try {
    const bytes = Uint8Array.from(cps.map((c) => (c <= 0xfe0f ? c - 0xfe00 : c - 0xe0100 + 16)));
    const s = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return printable(s) ? s : null;
  } catch { return null; }
}
function decodeBits(chars) {
  const u = [...new Set(chars)];
  if (u.length !== 2 || chars.length % 8) return null;
  for (const [, one] of [[u[0], u[1]], [u[1], u[0]]]) {
    let out = '';
    for (let i = 0; i < chars.length; i += 8) {
      let n = 0; for (let j = 0; j < 8; j++) n = (n << 1) | (chars[i + j] === one ? 1 : 0);
      out += String.fromCharCode(n);
    }
    if (/^[\x20-\x7e\n\t]+$/.test(out)) return out;
  }
  return null;
}

// ---------- the scanner ----------
export function scanText(text, opts = {}) {
  const file = opts.file || '<input>';
  const starts = lineIndex(text);
  const lines = text.split('\n');
  const findings = [];
  const seen = new Set();

  const push = (id, o) => {
    const [sev, title] = RULES[id];
    const loc = o.at != null ? locate(starts, o.at) : { line: o.line, col: o.col || 1 };
    const key = `${id}:${loc.line}:${loc.col}`;
    if (seen.has(key)) return;
    seen.add(key);
    const hits = o.hidden ? matchRules(o.hidden) : [];
    findings.push({
      id, severity: o.severity || sev, title, file, line: loc.line, col: loc.col,
      evidence: o.evidence, hidden: o.hidden, hiddenMatches: hits.length ? hits : undefined, span: o.span,
    });
  };

  // 1) invisible unicode ---------------------------------------------------
  const cps = [];
  for (let i = 0; i < text.length;) { const cp = text.codePointAt(i); const n = cp > 0xffff ? 2 : 1; cps.push([cp, i, i + n]); i += n; }
  const at = (k) => (k >= 0 && k < cps.length ? cps[k][0] : -1);
  const ch = (k) => (k >= 0 && k < cps.length ? String.fromCodePoint(cps[k][0]) : '');
  const runWhile = (k, pred) => { let e = k; while (e < cps.length && pred(cps[e][0])) e++; return e; };
  const span = (k, e) => [cps[k][1], cps[e - 1][2]];
  const label = (k, e) => {
    const n = e - k, uniform = cps.slice(k, e).every((x) => x[0] === cps[k][0]);
    return n === 1 ? cpHex(cps[k][0]) : uniform ? `${cpHex(cps[k][0])} ×${n}` : `${n} invisible chars, from ${cpHex(cps[k][0])}`;
  };

  for (let k = 0; k < cps.length;) {
    const cp = cps[k][0];
    if (cp >= 0x20 && cp < 0x7f) { k++; continue; }

    if (isTag(cp)) {
      const e = runWhile(k, isTag);
      const legitFlag = at(k - 1) === 0x1f3f4 && at(e - 1) === 0xe007f && e - k <= 8;
      if (!legitFlag) {
        const msg = decodeTags(cps.slice(k, e).map((x) => x[0]));
        push('GS001', { at: cps[k][1], span: span(k, e), hidden: msg || undefined, evidence: `${label(k, e)} (invisible)` });
      }
      k = e; continue;
    }
    if (isVS(cp)) {
      const e = runWhile(k, isVS), n = e - k, prev = at(k - 1);
      const keycap = at(e) === 0x20e3;
      if (n === 1 && (prev > 0x7f || keycap)) { k = e; continue; }          // normal emoji presentation
      if (n >= 2) {
        const msg = decodeVS(cps.slice(k, e).map((x) => x[0]));
        push('GS002', { at: cps[k][1], span: span(k, e), hidden: msg || undefined, severity: msg ? 'critical' : 'high', evidence: label(k, e) });
      } else push('GS002', { at: cps[k][1], span: span(k, e), severity: 'low', evidence: `stray ${label(k, e)} after ASCII` });
      k = e; continue;
    }
    if (ZW.has(cp)) {
      if (cp === 0xfeff && cps[k][1] === 0) { k++; continue; }                 // BOM
      const e = runWhile(k, (c) => ZW.has(c)), n = e - k;
      const before = at(k - 1), after = at(e);
      const emojiJoin = n === 1 && cp === 0x200d && (EMOJI.test(ch(k - 1)) || before === 0xfe0f) && EMOJI.test(ch(e));
      const scriptJoin = n === 1 && before > 0x7f && after > 0x7f;             // Persian, Indic, Thai, CJK...
      if (!emojiJoin && !scriptJoin) {
        const msg = n >= 8 ? decodeBits(cps.slice(k, e).map((x) => String.fromCodePoint(x[0]))) : null;
        push('GS003', {
          at: cps[k][1], span: span(k, e), hidden: msg || undefined,
          severity: msg ? 'critical' : n >= 8 ? 'high' : n >= 2 ? 'medium' : 'low', evidence: label(k, e),
        });
      }
      k = e; continue;
    }
    if (BIDI.has(cp)) { const e = runWhile(k, (c) => BIDI.has(c)); push('GS004', { at: cps[k][1], span: span(k, e), evidence: label(k, e) }); k = e; continue; }
    if (FILLER.has(cp)) {
      const e = runWhile(k, (c) => FILLER.has(c));
      push('GS005', { at: cps[k][1], span: span(k, e), severity: cp === 0x00ad && e - k === 1 ? 'low' : 'medium', evidence: label(k, e) });
      k = e; continue;
    }
    if (isCtl(cp)) {
      const e = runWhile(k, isCtl);
      push('GS007', { at: cps[k][1], span: span(k, e), evidence: cp === 0x1b ? 'ESC sequence (ANSI)' : label(k, e) });
      k = e; continue;
    }
    k++;
  }

  // 2) homoglyphs ----------------------------------------------------------
  if (/[^\x00-\x7f]/.test(text)) {
    for (const m of text.matchAll(/[\p{L}\p{N}]+/gu)) {
      const w = m[0];
      if (/[A-Za-z]/.test(w) && [...w].some((c) => CONFUSABLE.has(c))) {
        const bad = [...w].filter((c) => CONFUSABLE.has(c)).map((c) => `${c} ${cpHex(c.codePointAt(0))}`);
        push('GS006', { at: m.index, evidence: `"${w}" contains look-alike ${bad.join(', ')}` });
      }
    }
  }

  // 3) per-line text rules -------------------------------------------------
  const sinkLines = [], srcLines = [];
  lines.forEach((ln, i) => {
    if (!ln.trim()) return;
    for (const [id, re] of LINE_RULES) {
      const m = re.exec(ln);
      if (!m) continue;
      // "never read ~/.ssh" is a guardrail, not an attack: only a negation right before the path counts
      if (id === 'GS201') {
        const sentence = ln.slice(Math.max(0, m.index - 60), m.index).split(/[.!?;:]\s/).pop();
        if (!NEG.test(sentence)) srcLines.push([i, m, ln]);
        continue;
      }
      push(id, { line: i + 1, col: m.index + 1, evidence: snippet(ln, m.index, m[0].length) });
    }
    if (SINK.test(ln)) sinkLines.push(i);
    for (const re of SECRETS) {
      const m = re.exec(ln);
      if (m) push('GS401', { line: i + 1, col: m.index + 1, evidence: m[0].slice(0, 7) + '…(redacted)' });
    }
  });
  for (const [i, m, ln] of srcLines) {
    const chained = sinkLines.some((s) => Math.abs(s - i) <= 6);
    push(chained ? 'GS202' : 'GS201', { line: i + 1, col: m.index + 1, evidence: snippet(ln, m.index, m[0].length) });
  }

  // 4) multi-line / structural --------------------------------------------
  for (const m of text.matchAll(/<!--([\s\S]*?)-->/g)) {
    const body = m[1];
    if (matchRules(body).length || (AI_ADDR.test(body) && IMPERATIVE.test(body))) {
      push('GS104', { at: m.index, evidence: snippet(body.replace(/\s+/g, ' '), 0, 0, 140) });
    }
  }
  for (const m of text.matchAll(/!\[[^\]]*\]\(\s*(https?:\/\/[^)\s]+)|<img[^>]+src=["'](https?:\/\/[^"']+)/gi)) {
    const url = m[1] || m[2], q = url.split('?')[1];
    if (q && (/[{<$]|%7B|%3C/i.test(q) || /(^|&)(data|q|d|payload|secret|token|key|ctx|context|history|conversation)=/i.test(q))) {
      push('GS203', { at: m.index, evidence: snippet(url, 0, 0, 90) });
    }
  }
  for (const m of text.matchAll(/[A-Za-z0-9+/]{40,}={0,2}/g)) {
    if (/^[0-9a-f]+$/i.test(m[0])) continue;
    let dec; try { dec = typeof atob === 'function' ? atob(m[0]) : Buffer.from(m[0], 'base64').toString('latin1'); } catch { continue; }
    if (dec.length < 16 || !printable(dec) || /[\x00-\x08\x0e-\x1f]/.test(dec)) continue;
    const hits = matchRules(dec);
    push('GS402', { at: m.index, severity: hits.length ? 'high' : 'medium', hidden: dec.slice(0, 200), evidence: snippet(m[0], 0, 0, 24) });
  }

  // 5) JSON configs: MCP servers + hooks -----------------------------------
  if (opts.json ?? /\.json$/i.test(file)) scanConfig(text, starts, push);

  findings.sort((a, b) => SEV_ORDER.indexOf(b.severity) - SEV_ORDER.indexOf(a.severity) || a.line - b.line || a.col - b.col);
  const s = score(findings);
  return { file, findings, score: s, verdict: verdict(s) };
}

function scanConfig(text, starts, push) {
  let json; try { json = JSON.parse(text); } catch { return; }
  const lineOf = (needle) => { const i = text.indexOf(needle); return i < 0 ? 1 : locate(starts, i).line; };
  const servers = json?.mcpServers || json?.servers || json?.mcp?.servers;
  if (servers && typeof servers === 'object') {
    for (const [name, s] of Object.entries(servers)) {
      if (!s || typeof s !== 'object') continue;
      const line = lineOf(`"${name}"`);
      const args = Array.isArray(s.args) ? s.args.map(String) : [];
      const base = String(s.command || '').split(/[\\/]/).pop();
      const pkg = args.find((a) => !a.startsWith('-') && a !== 'dlx' && a !== 'run');
      if (/^(npx|bunx|pnpx)$/.test(base) || (base === 'pnpm' && args[0] === 'dlx')) {
        if (pkg && !/@v?\d[\w.+^~-]*$/.test(pkg)) push('GS501', { line, evidence: `${base} ${args.join(' ')}  → "${name}" runs whatever is "latest" on every launch` });
      } else if (/^(uvx|pipx)$/.test(base) && pkg && !/==|@\d/.test(pkg)) {
        push('GS501', { line, evidence: `${base} ${args.join(' ')}  → "${name}" is not pinned` });
      }
      const url = String(s.url || s.serverUrl || '');
      if (/^http:\/\//i.test(url) && !/^http:\/\/(localhost|127\.|\[::1\]|0\.0\.0\.0)/i.test(url)) {
        push('GS502', { line: lineOf(url), evidence: `${url} (server "${name}")` });
      }
    }
  }
  const walk = (v, path) => {
    if (Array.isArray(v)) return v.forEach((x) => walk(x, path));
    if (v && typeof v === 'object') return Object.entries(v).forEach(([k, x]) => walk(x, [...path, k]));
    if (typeof v === 'string' && path.includes('hooks') && path[path.length - 1] === 'command' &&
        (SINK.test(v) || /base64|\bnc\b|\|\s*(ba)?sh\b/.test(v))) {
      push('GS503', { line: lineOf(v.slice(0, 30)), evidence: snippet(v, 0, 0, 100) });
    }
  };
  walk(json, []);
}

export const score = (fs) => Math.min(100, fs.reduce((n, f) => n + WEIGHT[f.severity], 0));
export function verdict(s) {
  return s === 0 ? 'CLEAN' : s < 20 ? 'MINOR' : s < 40 ? 'SUSPICIOUS' : s < 70 ? 'DANGEROUS' : 'MALICIOUS';
}

// Remove every invisible / smuggling character we can safely delete.
export function strip(text) {
  const spans = scanText(text, { json: false }).findings.filter((f) => f.span).map((f) => f.span).sort((a, b) => b[0] - a[0]);
  let out = text;
  for (const [a, b] of spans) out = out.slice(0, a) + out.slice(b);
  return out;
}

// Split text into visible runs and hidden payloads — for "X-ray" rendering.
export function annotate(text) {
  const hid = scanText(text, { json: false }).findings.filter((f) => f.span).sort((a, b) => a.span[0] - b.span[0]);
  const segs = []; let pos = 0;
  for (const f of hid) {
    if (f.span[0] < pos) continue;
    if (f.span[0] > pos) segs.push({ text: text.slice(pos, f.span[0]) });
    segs.push({ hidden: true, id: f.id, label: f.evidence, decoded: f.hidden, severity: f.severity });
    pos = f.span[1];
  }
  if (pos < text.length) segs.push({ text: text.slice(pos) });
  return segs;
}
