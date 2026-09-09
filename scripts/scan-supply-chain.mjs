#!/usr/bin/env node
/**
 * Ellum AI — supply-chain / EtherHiding scanner.
 *
 * Detects the malware family that appends a blockchain-C2 dropper to source
 * files, hiding it behind a long run of tabs so it sits off-screen in editors
 * and collapses to "1 changed line" in review. The dropper reads its next
 * stage from Ethereum transaction data via public RPC endpoints and spawns it
 * detached, so there is no domain to block and no server to take down.
 *
 * Two variants observed in this org (2026-09):
 *   1. appended to `postcss.config.mjs`, with `createRequire(import.meta.url)`
 *      injected above it to hand the CommonJS payload a working `require`
 *   2. shipped as `public/fonts/fa-solid-500.woff2` — plain JS wearing a font
 *      extension, no WOFF2 magic bytes
 *
 * Zero dependencies. Exits 1 when anything critical/high is found.
 *
 * Usage:  node scan-supply-chain.mjs [rootDir]
 */

import { readFileSync, statSync, readdirSync, appendFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, extname, relative, basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** This scanner necessarily contains the patterns it hunts for. */
const SELF = fileURLToPath(import.meta.url);

const ROOT = process.argv[2] ? process.argv[2] : process.cwd();
const MAX_BYTES = 8 * 1024 * 1024; // skip anything larger; payloads are ~8KB

/* ── IOC literals are split so this scanner never matches itself ─────────── */
const C2_WALLET = '0xa322e5f3d311d3080e6f' + '0121063e9adc2490ef1a';
const MARK_NONCE = 'NONCE_' + 'FANO';
const MARK_BLOCK = 'BLOCK_' + 'MULTIPLE';

const ETH_RPC_HOSTS = [
  '1rpc' + '.io/eth',
  'eth' + '.drpc.org',
  'ethereum-rpc' + '.publicnode.com',
  'eth-mainnet' + '.public.blastapi.io',
  'eth' + '.blockscout.com',
];
const ETH_RPC_METHODS = [
  'eth_' + 'blockNumber',
  'eth_' + 'getBlockByNumber',
  'eth_' + 'getTransactionCount',
];

/* ── which files matter ──────────────────────────────────────────────────── */
const TEXT_EXT = new Set([
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx',
  '.json', '.yml', '.yaml', '.sh', '.bash', '.zsh', '.py', '.rb', '.php',
]);
const ASSET_EXT = new Set([
  '.woff2', '.woff', '.ttf', '.otf', '.png', '.jpg', '.jpeg', '.gif',
  '.webp', '.ico', '.wasm', '.pdf', '.mp4', '.avif', '.bmp',
]);
const MAGIC = {
  '.woff2': [[0x77, 0x4f, 0x46, 0x32]],
  '.woff': [[0x77, 0x4f, 0x46, 0x46]],
  '.ttf': [[0x00, 0x01, 0x00, 0x00], [0x74, 0x72, 0x75, 0x65], [0x74, 0x74, 0x63, 0x66]],
  '.otf': [[0x4f, 0x54, 0x54, 0x4f], [0x00, 0x01, 0x00, 0x00]],
  '.png': [[0x89, 0x50, 0x4e, 0x47]],
  '.jpg': [[0xff, 0xd8, 0xff]],
  '.jpeg': [[0xff, 0xd8, 0xff]],
  '.gif': [[0x47, 0x49, 0x46, 0x38]],
  '.webp': [[0x52, 0x49, 0x46, 0x46]],
  '.ico': [[0x00, 0x00, 0x01, 0x00]],
  '.wasm': [[0x00, 0x61, 0x73, 0x6d]],
  '.pdf': [[0x25, 0x50, 0x44, 0x46]],
  '.bmp': [[0x42, 0x4d]],
};
const CONFIG_RE = /(^|[/\\])(postcss|tailwind|next|metro|babel|vite|rollup|webpack|eslint|jest|vitest|svelte|nuxt|astro|expo|drizzle|prisma)\.config\.[cm]?[jt]s$/i;
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '.expo', 'out',
  'coverage', 'vendor', '.venv', 'venv', '__pycache__', '.turbo', '.cache',
  '.supply-chain-guard',
]);

/* ── allowlist: one path per line, '#' comments ──────────────────────────── */
let ALLOW = new Set();
for (const p of ['.github/supply-chain-allow.txt', '.supply-chain-allow']) {
  try {
    for (const line of readFileSync(join(ROOT, p), 'utf8').split('\n')) {
      const t = line.trim();
      if (t && !t.startsWith('#')) ALLOW.add(t);
    }
  } catch {}
}

const findings = [];
const add = (severity, rule, file, detail) =>
  findings.push({ severity, rule, file, detail });

/* ── file discovery: prefer git, fall back to a walk ─────────────────────── */
function listFiles() {
  try {
    const out = execFileSync('git', ['-C', ROOT, 'ls-files', '-z'], {
      maxBuffer: 64 * 1024 * 1024,
    });
    return out.toString('utf8').split('\0').filter(Boolean);
  } catch {
    const acc = [];
    (function walk(dir) {
      let entries;
      try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        if (e.name.startsWith('.') && e.name !== '.github') continue;
        if (SKIP_DIRS.has(e.name)) continue;
        const full = join(dir, e.name);
        if (e.isDirectory()) walk(full);
        else if (e.isFile()) acc.push(relative(ROOT, full));
      }
    })(ROOT);
    return acc;
  }
}

function isMostlyText(buf) {
  const n = Math.min(buf.length, 4096);
  if (n === 0) return false;
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const b = buf[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++;
  }
  return printable / n > 0.9;
}

function magicOk(ext, buf) {
  const sigs = MAGIC[ext];
  if (!sigs) return true;
  return sigs.some((sig) => sig.every((b, i) => buf[i] === b));
}

/* ── per-file rules ──────────────────────────────────────────────────────── */
function scanFile(rel) {
  if (ALLOW.has(rel)) return;
  const parts = rel.split(/[/\\]/);
  if (parts.some((p) => SKIP_DIRS.has(p))) return;

  const abs = join(ROOT, rel);
  if (resolve(abs) === SELF) return;
  let st;
  try { st = statSync(abs); } catch { return; }
  if (!st.isFile() || st.size === 0 || st.size > MAX_BYTES) return;

  const ext = extname(rel).toLowerCase();
  const isAsset = ASSET_EXT.has(ext);
  const isText = TEXT_EXT.has(ext);
  if (!isAsset && !isText && basename(rel) !== 'package.json') return;

  let buf;
  try { buf = readFileSync(abs); } catch { return; }

  /* R5 — an "asset" that is really source code */
  if (isAsset) {
    const textish = isMostlyText(buf);
    const badMagic = !magicOk(ext, buf);
    if (textish || badMagic) {
      const head = buf.subarray(0, 4096).toString('latin1');
      const looksJs =
        /\brequire\s*\(/.test(head) || /=>/.test(head) ||
        /\bfunction\b/.test(head) || /\bglobal\s*\./.test(head);
      if (textish && looksJs) {
        add('critical', 'masqueraded-asset', rel,
          `${ext} file contains JavaScript, not ${ext.slice(1)} data` +
          (badMagic ? ' (magic bytes absent)' : ''));
      } else if (badMagic && textish) {
        add('high', 'magic-mismatch', rel,
          `${ext} file has no valid ${ext.slice(1)} header and is ASCII text`);
      }
    }
    if (!isMostlyText(buf)) return; // real binary — nothing more to check
  }

  const content = buf.toString('utf8');
  const lower = content.toLowerCase();

  /* R1 — known C2 wallet */
  if (lower.includes(C2_WALLET)) {
    add('critical', 'known-c2-wallet', rel,
      'contains the EtherHiding C2 wallet address');
  }

  /* R2 — campaign markers */
  if (content.includes(MARK_NONCE) || content.includes(MARK_BLOCK)) {
    add('critical', 'campaign-marker', rel,
      'contains EtherHiding dropper constants');
  }

  /* R3 — require/module stashed on global (the dropper's bootstrap) */
  if (/global\s*\.\s*r\s*=\s*require/.test(content) ||
      /global\s*\.\s*m\s*=\s*module/.test(content) ||
      /typeof\s+module\s*&&\s*\(\s*global\s*\./.test(content)) {
    add('critical', 'global-require-stash', rel,
      'stashes require/module on global — dropper bootstrap pattern');
  }

  /* R4 — hidden-payload padding */
  const pad = content.match(/(\t{16,}|[ ]{200,})(?=\S)/);
  if (pad) {
    const kind = pad[1][0] === '\t' ? `${pad[1].length} tabs` : `${pad[1].length} spaces`;
    add('critical', 'hidden-payload-padding', rel,
      `${kind} of padding before code — used to push a payload off-screen`);
  }

  /* R6 — Ethereum RPC C2 */
  const hasRpcHost = ETH_RPC_HOSTS.some((h) => lower.includes(h));
  const hasRpcMethod = ETH_RPC_METHODS.some((m) => content.includes(m));
  const hasExec = /child_process|\bspawn\s*\(|\bexecSync\s*\(|\bexecFile\s*\(/.test(content);
  if ((hasRpcHost || hasRpcMethod) && hasExec) {
    add('critical', 'blockchain-c2', rel,
      'reads Ethereum RPC and spawns a process — blockchain C2 pattern');
  } else if (hasRpcHost && !hasRpcMethod) {
    add('medium', 'eth-rpc-endpoint', rel, 'references a public Ethereum RPC endpoint');
  }

  /* R7/R8/R10 — config files should not do any of this */
  if (CONFIG_RE.test(rel)) {
    if (hasExec) {
      add('critical', 'exec-in-config', rel,
        'build config spawns a child process');
    }
    if (/createRequire\s*\(\s*import\.meta\.url\s*\)/.test(content) &&
        !/\brequire\s*\(\s*['"]/.test(content.replace(/createRequire[^\n]*/g, ''))) {
      add('high', 'unused-createRequire', rel,
        'config injects createRequire() but never uses require() — ' +
        'the tell for a CommonJS payload appended below');
    }
    for (const [i, line] of content.split('\n').entries()) {
      if (line.length > 1000) {
        add('high', 'long-line-in-config', rel,
          `line ${i + 1} is ${line.length} chars — configs are not minified`);
        break;
      }
    }
  }

  /* R9 — install lifecycle scripts that fetch or eval */
  if (basename(rel) === 'package.json') {
    let pkg;
    try { pkg = JSON.parse(content); } catch { return; }
    for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
      const cmd = pkg?.scripts?.[hook];
      if (typeof cmd !== 'string') continue;
      if (/\b(curl|wget|node\s+-e|eval|base64\s+-d|iwr|invoke-webrequest)\b/i.test(cmd)) {
        add('high', 'risky-install-hook', rel,
          `"${hook}" fetches or evaluates code: ${cmd.slice(0, 120)}`);
      }
    }
  }
}

/* ── run ─────────────────────────────────────────────────────────────────── */
const files = listFiles();
for (const f of files) scanFile(f);

const order = { critical: 0, high: 1, medium: 2 };
findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file));

const counts = findings.reduce((m, f) => ((m[f.severity] = (m[f.severity] || 0) + 1), m), {});
const blocking = (counts.critical || 0) + (counts.high || 0);

const icon = { critical: '🚨', high: '⚠️ ', medium: 'ℹ️ ' };
if (findings.length === 0) {
  console.log(`✅ supply-chain scan clean — ${files.length} tracked files checked`);
} else {
  console.log(`\nSupply-chain scan — ${files.length} files checked, ${findings.length} finding(s)\n`);
  for (const f of findings) {
    console.log(`${icon[f.severity]} [${f.severity}] ${f.rule}`);
    console.log(`   ${f.file}`);
    console.log(`   ${f.detail}\n`);
  }
}

if (process.env.GITHUB_STEP_SUMMARY) {
  const lines = [];
  lines.push(findings.length === 0
    ? `## ✅ Supply-chain scan clean\n\n${files.length} tracked files checked.`
    : `## ${blocking ? '🚨' : 'ℹ️'} Supply-chain scan — ${findings.length} finding(s)\n`);
  if (findings.length) {
    lines.push('| Severity | Rule | File | Detail |');
    lines.push('| --- | --- | --- | --- |');
    for (const f of findings) {
      lines.push(`| ${f.severity} | \`${f.rule}\` | \`${f.file}\` | ${f.detail} |`);
    }
    if (blocking) {
      lines.push('\n**Do not merge.** Rotate any credential this repo can reach, then see');
      lines.push('[the org security policy](https://github.com/ellum-developers/.github/blob/main/SECURITY.md).');
    }
  }
  try { appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n'); } catch {}
}

if (blocking) {
  console.error(`\n❌ ${blocking} blocking finding(s): ${counts.critical || 0} critical, ${counts.high || 0} high`);
  process.exit(1);
}
console.log(findings.length ? '\n✅ no blocking findings' : '');
