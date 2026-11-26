// RepoCheck の誤報チェック用の検証台
//
// index.html の本物の処理（run → securityCheck）を Node.js の中でそのまま動かし、結果を集計する。
// 通信は横取りして tests/cache/ に保存するので、2回目からは GitHub や OSV.dev に問い合わせない。
// 判定ロジックを直したら、何度でもすぐに回し直せる。
//
// 使い方:
//   node tests/harness.mjs                 … 検証セット（tests/corpus.txt）と架空データを全部回す
//   node tests/harness.mjs owner/repo ...  … 指定したリポジトリだけ回す
//   node tests/harness.mjs --refresh       … 保存した通信を使わず取り直す
//
// GitHub への問い合わせには gh のログイン（gh auth token）を使う。トークンは保存しない。

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { fixtures } from './fixtures.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const CACHE = path.join(HERE, 'cache');
const args = process.argv.slice(2);
const REFRESH = args.includes('--refresh');
// --dump 出力先.json … 全リポジトリ・全架空データの判定結果（参考・安心材料・画面のHTMLも含む）を書き出す。書き換えの前後比較用
const dumpAt = args.indexOf('--dump');
const DUMP = dumpAt >= 0 ? args[dumpAt + 1] : null;
// --lang en … 英語表示で判定する（既定は日本語。ほかに zh-CN / zh-TW / ko）
const langAt = args.indexOf('--lang');
const LANG = langAt >= 0 ? args[langAt + 1] : 'ja';
// --corpus ファイル名 … 検証セットを指定（既定は corpus.txt。Hugging Face は corpus-hf.txt）
const corpusAt = args.indexOf('--corpus');
const CORPUS = corpusAt >= 0 ? args[corpusAt + 1] : 'corpus.txt';
const only = args.filter((a, i) => !a.startsWith('--') && !['--dump', '--lang', '--corpus'].includes(args[i - 1]));
const dump = { repos: {}, fixtures: {} };
fs.mkdirSync(CACHE, { recursive: true });

// ---------- 通信の横取りと保存 ----------
let netCount = 0;
async function cachedFetch(url, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase();
  const body = opts.body || '';
  const key = crypto.createHash('sha1').update(method + ' ' + url + ' ' + body).digest('hex');
  const file = path.join(CACHE, key + '.json');
  let rec;
  if (!REFRESH && fs.existsSync(file)) {
    rec = JSON.parse(fs.readFileSync(file, 'utf8'));
  } else {
    netCount++;
    const r = await fetch(url, opts);
    rec = { url, status: r.status, ratelimit: r.headers.get('x-ratelimit-remaining'), body: await r.text() };
    // 利用制限や一時的な失敗は保存しない（次回取り直す）
    if (![403, 429, 500, 502, 503, 504].includes(rec.status)) fs.writeFileSync(file, JSON.stringify(rec));
  }
  return {
    ok: rec.status >= 200 && rec.status < 300,
    status: rec.status,
    headers: { get: k => (k.toLowerCase() === 'x-ratelimit-remaining' ? rec.ratelimit : null) },
    json: async () => JSON.parse(rec.body),
    text: async () => rec.body,
  };
}

// ---------- 画面の部品の代わり（最低限） ----------
function fakeEl() {
  return {
    value: '', textContent: '', innerHTML: '', disabled: false, className: '', dataset: {},
    classList: { add() {}, remove() {} },
    addEventListener() {}, querySelectorAll: () => [], querySelector: () => null, scrollIntoView() {},
  };
}
const els = {};
const document = {
  getElementById: id => (els[id] ||= fakeEl()),
  querySelectorAll: () => [],
  querySelector: () => null,
  createElement: () => fakeEl(),
};

let token = '';
try { token = execFileSync('gh', ['auth', 'token'], { encoding: 'utf8' }).trim(); } catch { /* トークンなしで動かす */ }

const ctx = {
  document, fetch: cachedFetch, console, setTimeout, clearTimeout, TextDecoder, TextEncoder, URL,
  atob: s => Buffer.from(s, 'base64').toString('binary'),
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  navigator: { clipboard: { writeText: async () => {} }, language: LANG === 'en' ? 'en-US' : 'ja-JP', languages: [LANG === 'en' ? 'en-US' : 'ja-JP'] },
  __repocheckLang: LANG,
  __ghToken: token,
};
ctx.window = ctx;
vm.createContext(ctx);

// index.html の中の、いちばん長い <script> が本体
const INDEX = path.join(ROOT, 'index.html');
const html = fs.readFileSync(INDEX, 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).sort((a, b) => b.length - a.length);
const i18nFile = path.join(path.dirname(INDEX), 'i18n.js');
if (fs.existsSync(i18nFile)) vm.runInContext(fs.readFileSync(i18nFile, 'utf8'), ctx, { filename: 'i18n.js' });
vm.runInContext(scripts[0], ctx, { filename: 'index.html' });

// securityCheck の結果を横から受け取る
let captured = null;
const realCheck = ctx.securityCheck;
ctx.securityCheck = x => (captured = realCheck(x));
const realHF = ctx.hfCheck;
if (realHF) ctx.hfCheck = x => (captured = realHF(x));

const strip = s => String(s || '').replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/\s+/g, ' ').trim();

async function diagnose(repo) {
  captured = null;
  els.url.value = repo;
  els.status.textContent = '';
  await vm.runInContext('run()', ctx);
  if (!captured) return { repo, error: strip(els.status.textContent) || '結果なし' };
  if (DUMP) dump.repos[repo] = { sec: captured, html: els.out.innerHTML, status: els.status.textContent };
  return { repo, danger: captured.danger, warn: captured.warn, info: captured.info, good: captured.good };
}

// ---------- 実行 ----------
// 行頭に「!」が付いたものは「危険信号が出なければ失敗」（危険なデモ用リポジトリの見逃し確認）
const allEntries = only.length ? only : fs.readFileSync(path.join(HERE, CORPUS), 'utf8')
  .split('\n').map(l => l.replace(/#.*$/, '').trim()).filter(Boolean);
const mustFlag = allEntries.filter(e => e.startsWith('!')).map(e => e.slice(1).trim());
const corpus = allEntries.filter(e => !e.startsWith('!'));

const lines = [];
const out = s => { lines.push(s); console.log(s); };
let nD = 0, nW = 0, clean = 0, errors = 0;
const titleCount = {};

out('# 正規リポジトリでの判定（ここで出る危険信号・注意は誤報の候補）\n');
for (const repo of corpus) {
  const r = await diagnose(repo);
  if (r.error) { errors++; out(`- ❓ ${repo}：取得できず（${r.error}）`); continue; }
  nD += r.danger.length; nW += r.warn.length;
  if (!r.danger.length && !r.warn.length) { clean++; out(`- ✅ ${repo}`); continue; }
  out(`- ${r.danger.length ? '⛔' : '⚠'} ${repo}`);
  for (const [mark, arr] of [['危険', r.danger], ['注意', r.warn]]) {
    for (const s of arr) {
      titleCount[mark + '｜' + strip(s.t).replace(/\d[\d,]*/g, 'N')] = (titleCount[mark + '｜' + strip(s.t).replace(/\d[\d,]*/g, 'N')] || 0) + 1;
      out(`    - ${mark}：${strip(s.t)}\n      ${strip(s.x).slice(0, 220)}`);
    }
  }
}

let missed = 0;
if (mustFlag.length) {
  out('\n# 危険なはずのもの（危険信号が出ること）\n');
  for (const repo of mustFlag) {
    const r = await diagnose(repo);
    if (r.error) { missed++; out(`- ❌ ${repo}：取得できず（${r.error}）`); continue; }
    if (r.danger.length) out(`- ✅ ${repo}（危険${r.danger.length}：${r.danger.map(s => strip(s.t)).join('／').slice(0, 160)}）`);
    else { missed++; out(`- ❌ ${repo}：危険信号が出ない（注意${r.warn.length}）`); }
  }
}

out('\n# 架空データ（悪質な想定は検出し続け、健全な想定は静かであること）\n');
let fixFail = 0;
for (const f of fixtures) {
  const r = realCheck(f.input(Date.now()));
  if (DUMP) dump.fixtures[f.name] = r;
  const titles = [...r.danger.map(s => '危険:' + strip(s.t)), ...r.warn.map(s => '注意:' + strip(s.t)), ...r.info.map(s => '参考:' + strip(s.t))];
  const problems = [];
  // 見出しの文言で照合するのは日本語表示のときだけ（英語表示では、件数だけ確かめる）
  if (LANG === 'ja') {
    for (const want of f.must || []) if (!titles.some(t => t.includes(want))) problems.push('出るべき「' + want + '」が出ない');
    for (const ng of f.mustNot || []) { const hit = titles.find(t => t.includes(ng)); if (hit) problems.push('出てはいけない「' + hit + '」が出た'); }
  } else if ((f.mustNot || []).includes('注意:') && r.warn.length) problems.push('注意が出てはいけないのに ' + r.warn.length + ' 件出た');
  if (f.maxDanger !== undefined && r.danger.length > f.maxDanger) problems.push(`危険信号が ${r.danger.length} 件（上限 ${f.maxDanger}）`);
  if (f.minDanger !== undefined && r.danger.length < f.minDanger) problems.push(`危険信号が ${r.danger.length} 件（${f.minDanger} 件以上のはず）`);
  if (problems.length) { fixFail++; out(`- ❌ ${f.name}\n    - ${problems.join('\n    - ')}`); }
  else out(`- ✅ ${f.name}（危険${r.danger.length}・注意${r.warn.length}）`);
}

out('\n# 集計\n');
out(`- 正規リポジトリ ${corpus.length} 個：何も出ない ${clean} 個／危険信号 計${nD} 件／注意 計${nW} 件／取得できず ${errors} 個`);
out(`- 架空データ ${fixtures.length} 件：失敗 ${fixFail} 件`);
if (mustFlag.length) out(`- 危険なはずのもの ${mustFlag.length} 個：見逃し ${missed} 個`);
out(`- 今回の通信 ${netCount} 回（残りは保存済みの結果を使用）`);
const top = Object.entries(titleCount).sort((a, b) => b[1] - a[1]);
if (top.length) { out('\n## 多い指摘'); top.forEach(([t, n]) => out(`- ${n}回 ${t}`)); }

const miss = [...(ctx.__i18nMiss || [])];
if (!['ja', 'en'].includes(LANG)) {
  out(`\n# 訳が無かった英文（${LANG}）：${miss.length} 件`);
  miss.forEach(m => out('- ' + m.slice(0, 200)));
  if (DUMP) fs.writeFileSync(DUMP.replace(/\.json$/, '') + '-miss.json', JSON.stringify(miss, null, 1));
}
// --no-report … tests/last-report.md を書き換えない（pages/build.mjs から一部だけ回すとき用）
if (!args.includes('--no-report')) fs.writeFileSync(path.join(HERE, 'last-report.md'), lines.join('\n') + '\n');
if (DUMP) fs.writeFileSync(DUMP, JSON.stringify(dump, null, 1));
// 中国語・韓国語で訳の無い英文が出たら失敗にする
process.exit(fixFail || missed || (!['ja', 'en'].includes(LANG) && miss.length) ? 1 : 0);
