// 依存ライブラリの読み取り・OSV.dev の照合の部品テスト（通信はテスト用の偽の返事に差し替える）
// 使い方: node tests/unit.mjs   … 全部通れば終了コード0

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// 引数でほかの index.html を指定できる（直す前の版でテストが失敗するか＝テストが不具合を見つけられるかを確かめるため）
const html = fs.readFileSync(process.argv[2] || path.join(ROOT, 'index.html'), 'utf8');
const js = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).sort((a, b) => b.length - a.length)[0];

// ---- 偽の OSV.dev ----
// queries に対して返す脆弱性の番号と、番号ごとの詳細を決めておく
let osvBatch = {};      // 'npm:name@ver' → [id, ...]
let osvVulns = {};      // id → 詳細
let detailCalls = 0;
async function fakeFetch(url, opts = {}) {
  const ok = body => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => body, text: async () => JSON.stringify(body) });
  if (url === 'https://api.osv.dev/v1/querybatch') {
    const q = JSON.parse(opts.body).queries;
    return ok({ results: q.map(x => ({ vulns: (osvBatch[x.package.ecosystem + ':' + x.package.name + '@' + x.version] || []).map(id => ({ id })) })) });
  }
  const m = url.match(/^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/);
  if (m) { detailCalls++; const v = osvVulns[decodeURIComponent(m[1])]; return v ? ok(v) : { ok: false, status: 404, json: async () => ({}) }; }
  throw new Error('想定外の通信: ' + url);
}

const el = () => ({ value: '', textContent: '', addEventListener() {}, classList: { add() {}, remove() {} }, querySelectorAll: () => [] });
const ctx = {
  document: { getElementById: () => el(), querySelectorAll: () => [] }, fetch: fakeFetch, console, setTimeout, TextDecoder,
  localStorage: { getItem: () => null, setItem() {} }, navigator: { language: 'ja-JP' }, __repocheckLang: 'ja',
};
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(js, ctx);

let fail = 0, pass = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log('✅ ' + name); }
  else { fail++; console.log('❌ ' + name + (detail ? '\n   ' + detail : '')); }
}
const vuln = (id, pkg, sev, fixedList, aliases = []) => ({
  id, aliases, summary: id + ' の概要',
  database_specific: sev ? { severity: sev } : {},
  affected: [{ package: { name: pkg, ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: fixedList.flatMap(f => [{ introduced: '0' }, { fixed: f }]) }] }],
});

// ---------- 1. pyproject.toml の読み取り ----------
{
  const r = ctx.parseDeps({ reqRaws: [], pkgRaw: null, lockRaw: null, pyprojRaw:
    '[project]\nname = "x"\ndependencies = [\n  "uvicorn[standard]==0.30.0",\n  "fastapi==0.110.0",\n  "pydantic>=2",\n]\n[project.optional-dependencies]\ndev = ["pytest==8.0.0"]\n' });
  const names = r.pinned.map(d => d.name + '@' + d.ver);
  check('pyproject.toml：[standard] の ] で一覧が切れない', names.includes('uvicorn@0.30.0') && names.includes('fastapi@0.110.0'), JSON.stringify(names));
  check('pyproject.toml：optional-dependencies は読まない', !names.some(n => n.startsWith('pytest')), JSON.stringify(names));
  check('pyproject.toml：>= は版が決まっていない側', r.loose.some(d => d.name === 'pydantic'), JSON.stringify(r.loose));
}
// ---------- 2. requirements の * ----------
{
  const r = ctx.parseDeps({ pyprojRaw: null, pkgRaw: null, lockRaw: null, reqRaws: [{ name: 'requirements.txt', text: 'numpy==1.26.*\nrequests==2.31.0 \\\n    --hash=sha256:abc\n' }] });
  check('requirements：==1.26.* は版が決まっていない側', r.loose.some(d => d.name === 'numpy') && !r.pinned.some(d => d.name === 'numpy'), JSON.stringify(r));
  check('requirements：行の続き（\\ と --hash）でも版を読める', r.pinned.some(d => d.name === 'requests' && d.ver === '2.31.0'), JSON.stringify(r.pinned));
}
// ---------- 3. 重さ：GHSA を先に読む ----------
{
  osvBatch = { 'npm:a@1.0.0': ['PYSEC-1', 'GHSA-aaaa'] };
  osvVulns = { 'PYSEC-1': vuln('PYSEC-1', 'a', '', ['1.0.1'], ['GHSA-aaaa']), 'GHSA-aaaa': vuln('GHSA-aaaa', 'a', 'HIGH', ['1.0.1'], ['PYSEC-1']) };
  const d = await ctx.checkDeps({ reqRaws: [], pyprojRaw: null, lockRaw: null, pkgRaw: JSON.stringify({ dependencies: { a: '1.0.0' } }) });
  const v = d.vulnerable[0];
  check('同じ問題が2つの番号にあるとき、重さのある GHSA を使う（以前は不明になっていた）', v && v.top === 3 && v.count === 1, JSON.stringify(v));
}
// ---------- 4. 上限：最初の部品が使い切っても、後ろの部品の重さが分かる ----------
{
  osvBatch = {}; osvVulns = {};
  const many = Array.from({ length: 60 }, (_, i) => 'GHSA-big' + i);
  osvBatch['npm:big@1.0.0'] = many;
  many.forEach(id => (osvVulns[id] = vuln(id, 'big', 'LOW', ['1.0.1'])));
  osvBatch['npm:late@2.0.0'] = ['GHSA-late'];
  osvVulns['GHSA-late'] = vuln('GHSA-late', 'late', 'CRITICAL', ['2.0.5']);
  detailCalls = 0;
  const d = await ctx.checkDeps({ reqRaws: [], pyprojRaw: null, lockRaw: null, pkgRaw: JSON.stringify({ dependencies: { big: '1.0.0', late: '2.0.0' } }) });
  const late = d.vulnerable.find(v => v.name === 'late'), big = d.vulnerable.find(v => v.name === 'big');
  check('後ろの部品（late）の「緊急」を取りこぼさない', late && late.top === 4, JSON.stringify(late));
  check('件数は詳細を取らなかった分も数える（big は60件）', big && big.count === 60, JSON.stringify(big && { count: big.count, items: big.items.length }));
  check('部品ごとの上限（10件）を守る', detailCalls === 11, '詳細の取得回数 ' + detailCalls);
}
// ---------- 5. 直る版：今の系列の一番近い修正版 ----------
{
  osvBatch = { 'npm:vite@7.1.0': ['GHSA-v1', 'GHSA-v2'] }; osvVulns = {
    'GHSA-v1': vuln('GHSA-v1', 'vite', 'HIGH', ['6.4.4', '7.3.7', '8.3.3']),
    'GHSA-v2': vuln('GHSA-v2', 'vite', 'MODERATE', ['7.2.0', '8.0.1']),
  };
  const d = await ctx.checkDeps({ reqRaws: [], pyprojRaw: null, lockRaw: null, pkgRaw: JSON.stringify({ dependencies: { vite: '7.1.0' } }) });
  check('直る版は 7系の 7.3.7（8系の 8.3.3 にしない）', d.vulnerable[0] && d.vulnerable[0].fixTo === '7.3.7', JSON.stringify(d.vulnerable[0] && d.vulnerable[0].fixTo));
}
// ---------- 6. 重さ不明は「軽め」に入れない ----------
{
  const now = Date.now(), iso = x => new Date(now - x * 86400000).toISOString();
  const base = { repo: { created_at: iso(2000), stargazers_count: 5000, forks_count: 500, fork: false, has_issues: true }, owner: { created_at: iso(4000), type: 'Organization', login: 'o', followers: 10, public_repos: 10 },
    allPaths: [{ path: 'a.py', type: 'file' }], treeErr: false, readme: '', releases: [], advisories: [], scorecard: { __none: true }, pkgRaw: null, setupRaw: null };
  const deps = { pinned: [{}], loose: [], errors: [], malicious: [], vulnerable: [{ eco: 'PyPI', name: 'nosev', ver: '1.0', src: 'requirements.txt', dev: false, count: 5, items: [], top: 0, fixTo: '', sevUnknown: true }] };
  const r = ctx.securityCheck({ ...base, deps });
  const t = r.info.map(s => s.t).join(' / ');
  check('重さ不明の部品は「重さを確かめられなかった」と出る', /重さを確かめられなかった/.test(t) && !/軽め/.test(t), t);
}

// ---------- 7. npm 公式の安全な差し替え品 ----------
{
  osvBatch = { 'npm:fs@0.0.1-security': ['MAL-2025-21003'], 'npm:evil@1.0.0': ['MAL-2025-99999'] };
  osvVulns = { 'MAL-2025-21003': vuln('MAL-2025-21003', 'fs', '', []), 'MAL-2025-99999': vuln('MAL-2025-99999', 'evil', '', []) };
  const d = await ctx.checkDeps({ reqRaws: [], pyprojRaw: null, lockRaw: null, pkgRaw: JSON.stringify({ dependencies: { fs: '0.0.1-security', evil: '1.0.0' } }) });
  check('fs 0.0.1-security（npm 公式の差し替え品）は悪質扱いしない', !d.malicious.some(v => v.name === 'fs') && (d.placeholders || []).some(v => v.name === 'fs'), JSON.stringify({ mal: d.malicious.map(v => v.name), ph: (d.placeholders || []).map(v => v.name) }));
  check('本物の悪質パッケージは今までどおり悪質扱い', d.malicious.some(v => v.name === 'evil'), JSON.stringify(d.malicious.map(v => v.name)));
}

// ---------- 8. ロックファイル（間接的な部品） ----------
{
  // npm v3：入れ子・ワークスペース・リンク・開発用
  const lock = JSON.stringify({ lockfileVersion: 3, packages: {
    '': { name: 'app' },
    'node_modules/react': { version: '18.2.0' },
    'node_modules/minimist': { version: '1.2.5' },
    'node_modules/foo/node_modules/minimist': { version: '0.0.8' },
    'node_modules/eslint': { version: '8.0.0', dev: true },
    'packages/local': { version: '1.0.0' },
    'node_modules/linked': { link: true, resolved: 'packages/local' },
  } });
  const r = ctx.parseDeps({ reqRaws: [], pyprojRaw: null, poetryLockRaw: null, uvLockRaw: null, lockRaw: lock, pkgRaw: JSON.stringify({ dependencies: { react: '^18.0.0' } }) });
  const ids = r.pinned.map(d => d.name + '@' + d.ver + (d.indirect ? '(間接)' : '') + (d.dev ? '(開発)' : ''));
  check('npm v3：直接の react はロックファイルの版で直接扱い', ids.includes('react@18.2.0'), JSON.stringify(ids));
  check('npm v3：入れ子の別の版も両方照合する（minimist 1.2.5 と 0.0.8）', ids.includes('minimist@1.2.5(間接)') && ids.includes('minimist@0.0.8(間接)'), JSON.stringify(ids));
  check('npm v3：開発用の印が付く・ワークスペースとリンクは除く', ids.includes('eslint@8.0.0(間接)(開発)') && !ids.some(x => x.startsWith('local') || x.startsWith('linked')), JSON.stringify(ids));
}
{
  // npm v1：入れ子の dependencies
  const lock = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0', dev: true } } } } });
  const r = ctx.parseDeps({ reqRaws: [], pyprojRaw: null, poetryLockRaw: null, uvLockRaw: null, lockRaw: lock, pkgRaw: JSON.stringify({ dependencies: {} }) });
  check('npm v1：入れ子の部品まで読む', r.pinned.some(d => d.name === 'b' && d.ver === '2.0.0' && d.indirect && d.dev), JSON.stringify(r.pinned));
}
{
  // poetry.lock：[package.dependencies] の中の name を取り違えない・category と groups
  const poetry = '[[package]]\nname = "requests"\nversion = "2.19.0"\ncategory = "main"\n\n[package.dependencies]\nname = "should-not-read"\n\n[[package]]\nname = "pytest"\nversion = "7.0.0"\ngroups = ["dev"]\n\n[[package]]\nname = "Pydantic"\nversion = "2.5.0"\ngroups = ["main"]\n';
  const r = ctx.parseDeps({ reqRaws: [{ name: 'requirements.txt', text: 'pydantic>=2\n' }], pyprojRaw: null, lockRaw: null, uvLockRaw: null, pkgRaw: null, poetryLockRaw: poetry });
  const ids = r.pinned.map(d => d.name + '@' + d.ver + (d.indirect ? '(間接)' : '') + (d.dev ? '(開発)' : ''));
  check('poetry.lock：間接の requests・開発用の pytest を読む（下位の表の name は読まない）', ids.includes('requests@2.19.0(間接)') && ids.includes('pytest@7.0.0(間接)(開発)') && !ids.some(x => x.startsWith('should-not-read')), JSON.stringify(ids));
  check('poetry.lock：版を決めていなかった pydantic>=2 を、ロックファイルの 2.5.0 で直接扱いに', ids.includes('pydantic@2.5.0') && !r.loose.some(d => d.name === 'pydantic'), JSON.stringify({ ids, loose: r.loose }));
}
{
  // uv.lock：自分自身（editable / virtual）を除く
  const uv = '[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "httpx"\nversion = "0.27.0"\nsource = { registry = "https://pypi.org/simple" }\n';
  const r = ctx.parseDeps({ reqRaws: [], pyprojRaw: null, lockRaw: null, poetryLockRaw: null, pkgRaw: null, uvLockRaw: uv });
  check('uv.lock：自分自身は除き、httpx は読む', r.pinned.some(d => d.name === 'httpx' && d.indirect) && !r.pinned.some(d => d.name === 'myapp'), JSON.stringify(r.pinned));
}
{
  // 1,000個を超えるときは分けて送る。後ろの方にある悪質パッケージも見つける
  const pk = { '': {} };
  for (let i = 0; i < 1500; i++) pk['node_modules/p' + i] = { version: '1.0.0' };
  osvBatch = { 'npm:p1400@1.0.0': ['MAL-2026-1'] }; osvVulns = { 'MAL-2026-1': vuln('MAL-2026-1', 'p1400', '', []) };
  const d = await ctx.checkDeps({ reqRaws: [], pyprojRaw: null, poetryLockRaw: null, uvLockRaw: null, pkgRaw: JSON.stringify({ dependencies: {} }), lockRaw: JSON.stringify({ lockfileVersion: 3, packages: pk }) });
  check('1,000個を超えても、1,400番目の悪質パッケージを見つける', d.malicious.some(v => v.name === 'p1400' && v.indirect), JSON.stringify(d.malicious.map(v => v.name)));
}
{
  // 判定：間接の悪質は危険信号、間接の重大な脆弱性は参考
  const now = Date.now(), iso = x => new Date(now - x * 86400000).toISOString();
  const base = { repo: { created_at: iso(2000), stargazers_count: 5000, forks_count: 500, fork: false, has_issues: true }, owner: { created_at: iso(4000), type: 'Organization', login: 'o', followers: 10, public_repos: 10 },
    allPaths: [{ path: 'a.js', type: 'file' }], treeErr: false, readme: '', releases: [], advisories: [], scorecard: { __none: true }, pkgRaw: null, setupRaw: null };
  const mal = { eco: 'npm', name: 'evil-sub', ver: '1.0.0', src: 'package-lock.json', dev: false, indirect: true, count: 1, items: [], top: 0, fixTo: '' };
  const sev = { eco: 'npm', name: 'old-sub', ver: '1.0.0', src: 'package-lock.json', dev: false, indirect: true, count: 3, items: [], top: 4, fixTo: '1.2.0' };
  const r = ctx.securityCheck({ ...base, deps: { pinned: [{}], loose: [], errors: [], malicious: [mal], vulnerable: [mal, sev] } });
  check('間接的な部品でも、悪質パッケージは危険信号', r.danger.some(s => /悪意のあるパッケージ/.test(s.t)), JSON.stringify(r.danger.map(s => s.t)));
  check('間接的な部品の重大な脆弱性は「注意」ではなく「参考」', !r.warn.some(s => /依存ライブラリ/.test(s.t)) && r.info.some(s => /間接的に使われる部品/.test(s.t)), JSON.stringify({ warn: r.warn.map(s => s.t), info: r.info.map(s => s.t) }));
}

{
  // Python のロックファイルからだけ版が分かった直接の部品は「参考」。作者が == で固定したものは「注意」
  const now = Date.now(), iso = x => new Date(now - x * 86400000).toISOString();
  const base = { repo: { created_at: iso(2000), stargazers_count: 5000, forks_count: 500, fork: false, has_issues: true }, owner: { created_at: iso(4000), type: 'Organization', login: 'o', followers: 10, public_repos: 10 },
    allPaths: [{ path: 'a.py', type: 'file' }], treeErr: false, readme: '', releases: [], advisories: [], scorecard: { __none: true }, pkgRaw: null, setupRaw: null };
  const locked = { eco: 'PyPI', name: 'anyio', ver: '4.12.1', src: 'uv.lock', dev: false, lockOnly: true, count: 2, items: [], top: 4, fixTo: '4.14.2' };
  const pinnedByAuthor = { eco: 'PyPI', name: 'aiohttp', ver: '3.12.13', src: 'pyproject.toml', dev: false, count: 5, items: [], top: 3, fixTo: '3.14.4' };
  const r = ctx.securityCheck({ ...base, deps: { pinned: [{}], loose: [], errors: [], malicious: [], vulnerable: [locked, pinnedByAuthor] } });
  const w = r.warn.map(s => s.x).join(' '), i = r.info.map(s => s.t).join(' / ');
  check('Python のロックファイルだけの版（anyio）は「参考」、作者が固定した版（aiohttp）は「注意」', /aiohttp/.test(w) && !/anyio/.test(w) && /ロックファイルに書かれた版/.test(i), JSON.stringify({ w, i }));
  const p = ctx.parseDeps({ reqRaws: [], pyprojRaw: '[project]\ndependencies = ["anyio>=3"]\n', lockRaw: null, poetryLockRaw: null, pkgRaw: null, uvLockRaw: '[[package]]\nname = "anyio"\nversion = "4.12.1"\nsource = { registry = "x" }\n' });
  check('uv.lock で版が分かった直接の部品に lockOnly が付く', p.pinned.some(d => d.name === 'anyio' && d.lockOnly && !d.indirect), JSON.stringify(p.pinned));
}

{
  // 開発用の目印：-e . を含む requirements／Python のプロジェクトの private な package.json
  const r1 = ctx.parseDeps({ reqRaws: [{ name: 'requirements.txt', text: '-e .[cli]\ncryptography==45.0.7\n' }], pyprojRaw: null, lockRaw: null, poetryLockRaw: null, uvLockRaw: null, pkgRaw: null });
  check('-e . を含む requirements の部品は開発用', r1.pinned.some(d => d.name === 'cryptography' && d.dev && d.src === 'requirements.txt'), JSON.stringify(r1.pinned));
  const r2 = ctx.parseDeps({ reqRaws: [{ name: 'requirements.txt', text: 'cryptography==45.0.7\n' }], pyprojRaw: null, lockRaw: null, poetryLockRaw: null, uvLockRaw: null, pkgRaw: null });
  check('-e . が無い requirements の部品は本番用のまま', r2.pinned.some(d => d.name === 'cryptography' && !d.dev), JSON.stringify(r2.pinned));
  const pj = JSON.stringify({ private: true, dependencies: { handlebars: '4.7.9' } });
  const r3 = ctx.parseDeps({ reqRaws: [], pyprojRaw: '[project]\nname="x"\n', lockRaw: null, poetryLockRaw: null, uvLockRaw: null, pkgRaw: pj });
  const r4 = ctx.parseDeps({ reqRaws: [], pyprojRaw: null, lockRaw: null, poetryLockRaw: null, uvLockRaw: null, pkgRaw: pj });
  check('Python のプロジェクトの private な package.json の部品は開発用', r3.pinned.some(d => d.name === 'handlebars' && d.dev), JSON.stringify(r3.pinned));
  check('JavaScript だけのプロジェクトの private な package.json の部品は本番用のまま（Bitwarden 型）', r4.pinned.some(d => d.name === 'handlebars' && !d.dev), JSON.stringify(r4.pinned));
}

// ---------- 9. pnpm・yarn・bun のロックファイル ----------
{
  const pkg = JSON.stringify({ dependencies: { react: '^18.0.0' }, devDependencies: { vitest: '^1.0.0', local: 'workspace:*' } });
  const P = extra => ctx.parseDeps({ reqRaws: [], pyprojRaw: null, lockRaw: null, poetryLockRaw: null, uvLockRaw: null, pkgRaw: pkg, ...extra });
  const ids = r => r.pinned.map(d => d.name + '@' + d.ver + (d.indirect ? '(間接)' : '') + (d.dev ? '(開発)' : ''));

  // pnpm 版9（書類が2つ・付記つきの版・名前に @ がある部品）
  const v9 = "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    packageManagerDependencies:\n      pnpm:\n        specifier: 9.0.0\n        version: 9.0.0\n\npackages:\n\n  pnpm@9.0.0:\n    resolution: {integrity: x}\n\n---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      react:\n        specifier: ^18.0.0\n        version: 18.2.0\n    devDependencies:\n      vitest:\n        specifier: ^1.0.0\n        version: 1.6.0(@types/node@20.0.0)\n      local:\n        specifier: workspace:*\n        version: link:packages/local\n\npackages:\n\n  react@18.2.0:\n    resolution: {integrity: x}\n\n  '@types/node@20.0.0':\n    resolution: {integrity: x}\n\n  vitest@1.6.0:\n    resolution: {integrity: x}\n\nsnapshots:\n\n  vitest@1.6.0(@types/node@20.0.0):\n    dependencies:\n      '@types/node': 20.0.0\n";
  const r9 = P({ pnpmLockRaw: v9 });
  check('pnpm 版9：直接の react・vitest の実際の版（付記を外す）', ids(r9).includes('react@18.2.0') && ids(r9).includes('vitest@1.6.0(開発)'), JSON.stringify(ids(r9)));
  check('pnpm 版9：間接の @types/node・2つ目の書類の pnpm も読む／workspace: の自分自身は照合の対象から外す', ids(r9).includes('@types/node@20.0.0(間接)') && ids(r9).includes('pnpm@9.0.0(間接)') && !r9.loose.some(d => d.name === 'local') && !r9.pinned.some(d => d.name === 'local'), JSON.stringify({ ids: ids(r9), loose: r9.loose }));
  // pnpm 版6（/名前@版・dev: true）と版5（/名前/版_付記）
  const v6 = "lockfileVersion: '6.0'\n\nimporters:\n\n  .:\n    dependencies:\n      react:\n        specifier: ^18.0.0\n        version: 18.2.0\n\npackages:\n\n  /react@18.2.0:\n    resolution: {integrity: x}\n    dev: false\n\n  /@babel/core@7.24.0:\n    resolution: {integrity: x}\n    dev: true\n";
  const r6 = P({ pnpmLockRaw: v6 });
  check('pnpm 版6：/名前@版 を読み、dev: true を開発用にする', ids(r6).includes('@babel/core@7.24.0(間接)(開発)') && ids(r6).includes('react@18.2.0'), JSON.stringify(ids(r6)));
  const v5 = "lockfileVersion: 5.4\n\nspecifiers:\n  react: ^18.0.0\n\ndependencies:\n  react: 18.2.0\n\npackages:\n\n  /react/18.2.0:\n    resolution: {integrity: x}\n\n  /@babel/core/7.12.3_supports-color@5.5.0:\n    resolution: {integrity: x}\n    dev: true\n";
  const r5 = P({ pnpmLockRaw: v5 });
  check('pnpm 版5：/名前/版 と _付記 を読む', ids(r5).includes('react@18.2.0') && ids(r5).includes('@babel/core@7.12.3(間接)(開発)'), JSON.stringify(ids(r5)));

  // yarn 旧形式（v1）：複数の範囲・別名
  const y1 = '# yarn lockfile v1\n\n\n"react@^18.0.0", react@^18.2.0:\n  version "18.2.0"\n  resolved "https://registry.yarnpkg.com/react/-/react-18.2.0.tgz"\n\nvitest@^1.0.0:\n  version "1.6.0"\n\n"old-name@npm:lodash@^4.17.0":\n  version "4.17.21"\n';
  const ry1 = P({ yarnLockRaw: y1 });
  check('yarn 旧形式：範囲から直接の版を引く・別名は本当の名前（lodash）で照合', ids(ry1).includes('react@18.2.0') && ids(ry1).includes('vitest@1.6.0(開発)') && ids(ry1).includes('lodash@4.17.21(間接)') && !ids(ry1).some(x => x.includes('old-name')), JSON.stringify(ids(ry1)));
  // yarn 新形式：workspace・patch を除く
  const y2 = '__metadata:\n  version: 8\n\n"react@npm:^18.0.0":\n  version: 18.2.0\n  resolution: "react@npm:18.2.0"\n\n"local@workspace:packages/local":\n  version: 0.0.0-use.local\n  resolution: "local@workspace:packages/local"\n\n"fsevents@patch:fsevents@npm%3A2.3.3#~/.yarn/patches/x.patch":\n  version: 2.3.3\n  resolution: "fsevents@patch:fsevents@npm%3A2.3.3#~/.yarn/patches/x.patch::version=2.3.3"\n\n"real@npm:1.0.0, alias@npm:real@1.0.0":\n  version: 1.0.0\n  resolution: "real@npm:1.0.0"\n';
  const ry2 = P({ yarnLockRaw: y2 });
  check('yarn 新形式：npm の部品だけ読み、workspace と patch は除く', ids(ry2).includes('react@18.2.0') && ids(ry2).includes('real@1.0.0(間接)') && !ids(ry2).some(x => /local|fsevents|alias/.test(x)), JSON.stringify(ids(ry2)));

  // bun.lock：末尾のカンマ・入れ子の版・workspace
  const bl = '{\n  "lockfileVersion": 1,\n  "workspaces": { "": { "name": "app", "dependencies": { "react": "^18.0.0", }, }, },\n  "packages": {\n    "react": ["react@18.2.0", "", {}, "sha512-x"],\n    "vitest": ["vitest@1.6.0", "", {}, "sha512-x"],\n    "vitest/tinypool": ["tinypool@0.8.4", "", {}, "sha512-x"],\n    "local": ["local@workspace:packages/local"],\n  },\n}\n';
  const rb = P({ bunLockRaw: bl });
  check('bun.lock：末尾のカンマがあっても読む・入れ子の tinypool も読む・workspace は除く', ids(rb).includes('react@18.2.0') && ids(rb).includes('tinypool@0.8.4(間接)') && !ids(rb).some(x => x.startsWith('local@')), JSON.stringify(ids(rb)));

  // 古い bun.lockb：読めないことを、脆弱性が無いときも表示する
  const rl = P({ bunLockb: true });
  check('bun.lockb は「読めなかったファイル」に入る', rl.errors.some(e => e.file === 'bun.lockb' && e.why === 'binary'), JSON.stringify(rl.errors));
  const html = ctx.renderDeps({ ...rl, vulnerable: [], malicious: [], err: null });
  check('bun.lockb の注記は、脆弱性が無いときも画面に出る', /bun\.lockb/.test(html) && /読めません/.test(html), html.slice(-200));
}

// ---------- 10. npm に同じ名前の悪質パッケージがある、リポジトリ内の部品・別名（React で誤報） ----------
{
  const pkg = JSON.stringify({ devDependencies: {
    'eslint-plugin-react-internal': 'link:./scripts/eslint-rules',
    'eslint-plugin-react-hooks-published': 'npm:eslint-plugin-react-hooks@^5.2.0',
    'my-local': 'file:../local', 'ws-pkg': 'workspace:*', 'gh-pkg': 'github:user/repo' } });
  const yl = '# yarn lockfile v1\n\n\n"eslint-plugin-react-internal@link:./scripts/eslint-rules":\n  version "0.0.0"\n  uid ""\n\n"eslint-plugin-react-hooks-published@npm:eslint-plugin-react-hooks@^5.2.0":\n  version "5.2.0"\n  resolved "https://registry.yarnpkg.com/eslint-plugin-react-hooks/-/eslint-plugin-react-hooks-5.2.0.tgz"\n';
  const r = ctx.parseDeps({ reqRaws: [], pyprojRaw: null, lockRaw: null, poetryLockRaw: null, uvLockRaw: null, pkgRaw: pkg, yarnLockRaw: yl });
  const names = r.pinned.map(d => d.name + '@' + d.ver + (d.indirect ? '(間接)' : ''));
  check('link:・file:・workspace:・github: の部品は照合しない（npm の同名の悪質パッケージに当たらない）', !r.pinned.some(d => /react-internal|my-local|ws-pkg|gh-pkg/.test(d.name)) && !r.loose.some(d => /react-internal|my-local|ws-pkg|gh-pkg/.test(d.name)), JSON.stringify({ names, loose: r.loose }));
  check('別名 npm:eslint-plugin-react-hooks@^5.2.0 は本当の名前で照合する（直接）', names.includes('eslint-plugin-react-hooks@5.2.0') && !names.some(x => x.includes('-published')), JSON.stringify(names));
  // package-lock の別名
  const pl = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/eslint-plugin-react-hooks-published': { name: 'eslint-plugin-react-hooks', version: '5.2.0', dev: true } } });
  const r2 = ctx.parseDeps({ reqRaws: [], pyprojRaw: null, poetryLockRaw: null, uvLockRaw: null, pkgRaw: pkg, lockRaw: pl });
  check('package-lock の別名も本当の名前で照合する', r2.pinned.some(d => d.name === 'eslint-plugin-react-hooks' && d.ver === '5.2.0') && !r2.pinned.some(d => d.name.includes('-published')), JSON.stringify(r2.pinned));
  // pnpm の別名（importers の version が「本当の名前@版」）
  const pn = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    devDependencies:\n      eslint-plugin-react-hooks-published:\n        specifier: npm:eslint-plugin-react-hooks@^5.2.0\n        version: eslint-plugin-react-hooks@5.2.0\n\npackages:\n\n  eslint-plugin-react-hooks@5.2.0:\n    resolution: {integrity: x}\n";
  const r3 = ctx.parseDeps({ reqRaws: [], pyprojRaw: null, lockRaw: null, poetryLockRaw: null, uvLockRaw: null, pkgRaw: JSON.stringify({ devDependencies: { 'eslint-plugin-react-hooks-published': 'npm:eslint-plugin-react-hooks@^5.2.0' } }), pnpmLockRaw: pn });
  check('pnpm の別名も本当の名前で照合する', r3.pinned.some(d => d.name === 'eslint-plugin-react-hooks' && d.ver === '5.2.0' && !d.indirect) && !r3.pinned.some(d => d.name.includes('-published')), JSON.stringify(r3.pinned));
}

{
  // 別名で開発用の欄に入れた部品は、ロックファイルの版で補ったあとも開発用（angular で誤報）
  const pn = "lockfileVersion: '9.0'\n\npackages:\n\n  angular@1.5.11:\n    resolution: {integrity: x}\n";
  const r = ctx.parseDeps({ reqRaws: [], pyprojRaw: null, lockRaw: null, poetryLockRaw: null, uvLockRaw: null, pkgRaw: JSON.stringify({ devDependencies: { 'angular-1.5': 'npm:angular@1.5' } }), pnpmLockRaw: pn });
  check('開発用の欄の別名は、補ったあとも開発用', r.pinned.some(d => d.name === 'angular' && d.ver === '1.5.11' && d.dev && !d.indirect), JSON.stringify(r.pinned));
}
{
  // 二重拡張子：robots.txt.js は危険にしない・.pdf.exe は危険のまま
  const now = Date.now(), iso = x => new Date(now - x * 86400000).toISOString();
  const base = { repo: { created_at: iso(2000), stargazers_count: 5000, forks_count: 500, fork: false, has_issues: true }, owner: { created_at: iso(4000), type: 'Organization', login: 'o', followers: 10, public_repos: 10 },
    treeErr: false, readme: '', releases: [], advisories: [], scorecard: { __none: true }, pkgRaw: null, setupRaw: null, deps: null };
  const r1 = ctx.securityCheck({ ...base, allPaths: [{ path: 'src/a.js', type: 'file' }, { path: 'src/routes/robots.txt.js', type: 'file' }, { path: 'test/samples/foo.txt.js', type: 'file' }] });
  const r2 = ctx.securityCheck({ ...base, allPaths: [{ path: 'src/a.js', type: 'file' }, { path: 'docs/manual.pdf.exe', type: 'file' }] });
  check('robots.txt.js（Web フレームワークの命名）は偽装扱いしない', !r1.danger.some(s => /偽装/.test(s.t)), JSON.stringify(r1.danger.map(s => s.t)));
  check('manual.pdf.exe は今までどおり偽装の危険信号', r2.danger.some(s => /拡張子を偽装/.test(s.t)), JSON.stringify(r2.danger.map(s => s.t)));
}

// ---------- 11. Hugging Face ----------
{
  const P = ctx.parseHF;
  const eq = (u, want) => JSON.stringify(P(u)) === JSON.stringify(want);
  check('URL の読み取り：モデル・データセット・Space・昔の名前・hf.co・ページ内の下位パス',
    eq('https://huggingface.co/openai/whisper-large-v3', { kind: 'model', id: 'openai/whisper-large-v3' })
    && eq('https://huggingface.co/datasets/rajpurkar/squad', { kind: 'dataset', id: 'rajpurkar/squad' })
    && eq('huggingface.co/spaces/openai/whisper', { kind: 'space', id: 'openai/whisper' })
    && eq('https://huggingface.co/bert-base-uncased', { kind: 'model', id: 'bert-base-uncased' })
    && eq('https://hf.co/openai/whisper-large-v3/tree/main/assets?x=1', { kind: 'model', id: 'openai/whisper-large-v3' })
    && eq('https://huggingface.co/bert-base-uncased/blob/main/config.json', { kind: 'model', id: 'bert-base-uncased' }),
    JSON.stringify(['https://huggingface.co/bert-base-uncased/blob/main/config.json'].map(P)));
  check('URL の読み取り：説明ページ・作者なしの Space は不正、GitHub の URL は対象外',
    P('https://huggingface.co/docs/hub')?.bad && P('https://huggingface.co/spaces/whisper')?.bad && P('https://github.com/openai/whisper') === null, '');

  const now = Date.now(), iso = d => new Date(now - d * 86400000).toISOString();
  const oid = d => Math.floor((now - d * 86400000) / 1000).toString(16).padStart(8, '0') + '0000000000000000';
  check('作者の作成日を ID から取り出す', Math.abs(new Date(ctx.hfCreated(oid(100))) - (now - 100 * 86400000)) < 2000, ctx.hfCreated(oid(100)));
  const base = (over = {}) => ({ kind: 'model', files: ['README.md', 'config.json', 'model.safetensors'], readme: '', deps: null, fileSec: null,
    info: { createdAt: iso(500), likes: 5, downloads: 10, securityRepoStatus: { scansDone: true, filesWithIssues: [] }, config: {} },
    owner: { type: 'user', login: 'someone', created: iso(1000), verified: false, followers: 3, models: 2 }, ...over });
  const T = r => [...r.danger.map(s => '危険:' + s.t), ...r.warn.map(s => '注意:' + s.t), ...r.info.map(s => '参考:' + s.t)].join(' / ');
  const H = x => ctx.hfCheck(x);

  let r = H(base({ owner: { type: 'user', login: 'newbie', created: iso(5), verified: false, followers: 0, models: 1 }, files: ['README.md', 'pytorch_model.bin'] }));
  check('できたてのアカウント＋pickle だけ → 危険信号と注意', /危険:作者のアカウントが作られて/.test(T(r)) && /注意:読み込むだけでプログラムが動きうる形式/.test(T(r)), T(r));
  r = H(base({ files: ['README.md', 'ggml-model-q4_0.bin', 'model-Q4_K_M.gguf'] }));
  check('GGML の .bin は pickle 扱いしない', !/pickle/.test(T(r)), T(r));
  for (const name of ['meta-Ilama', '0penai', 'stabilityaii', 'openai-official']) {
    r = H(base({ owner: { type: 'user', login: name, created: iso(60), verified: false, followers: 0, models: 1 } }));
    check('なりすましの名前「' + name + '」を見つける', /注意:有名な組織/.test(T(r)), T(r));
  }
  for (const [name, verified] of [['openai-community', false], ['facebook', false], ['meta-llama', true], ['openai-official', true]]) {
    r = H(base({ owner: { type: 'org', login: name, created: iso(1500), verified, followers: 9, models: 9 } }));
    check('本物・確認済みの「' + name + '」はなりすまし扱いしない', !/有名な組織/.test(T(r)), T(r));
  }
  r = H(base({ info: { ...base().info, config: { auto_map: { AutoModel: 'modeling_x.X' } } }, files: ['README.md', 'modeling_x.py', 'model.safetensors'] }));
  check('実績の少ない作者の trust_remote_code → 注意', /注意:読み込むときに作者のプログラムが動きます/.test(T(r)), T(r));
  r = H(base({ files: ['README.md', 'infer.py', 'model.safetensors'] }));
  check('自分で実行するスクリプト（infer.py）は trust_remote_code 扱いしない', !/trust_remote_code/.test(T(r)) && /参考:Python のプログラムが含まれています/.test(T(r)), T(r));

  const flag = (path, level) => ({ ...base().info, securityRepoStatus: { scansDone: true, filesWithIssues: [{ path, level }] } });
  const st = o => ({ status: 'unsafe', protectAiScan: { status: 'unsafe', message: 'PAIT-PKL-100' }, avScan: { status: 'safe' }, pickleImportScan: { status: 'unscanned', pickleImports: [] }, virusTotalScan: { status: 'safe' }, ...o });
  r = H(base({ info: flag('a.pkl', 'unsafe'), fileSec: { 'a.pkl': st({ avScan: { status: 'unsafe', message: 'Detected malware signatures: Py.Malware.X' } }) } }));
  check('ウイルス対策ソフトの検出 → 危険信号（検出名つき）', /危険:Hugging Face の自動検査で、ウイルス/.test(T(r)) && /Py\.Malware\.X/.test(r.danger[0].x), T(r));
  r = H(base({ info: flag('b.pkl', 'unsafe'), fileSec: { 'b.pkl': st({ pickleImportScan: { status: 'unsafe', pickleImports: [{ module: 'builtins', name: 'exec', safety: 'dangerous' }] } }) } }));
  check('pickle の中に exec → 危険信号', /危険:Hugging Face の自動検査で、ウイルス/.test(T(r)) && /builtins\.exec/.test(r.danger[0].x), T(r));
  r = H(base({ info: flag('c.7z', 'unsafe'), fileSec: { 'c.7z': st({}) } }));
  check('ProtectAI の一般的な指摘だけ → 危険ではなく注意（RVC 型）', !r.danger.length && /注意:Hugging Face が「unsafe」と表示/.test(T(r)), T(r));
  r = H(base({ info: flag('d.bin', 'unsafe'), fileSec: null }));
  check('詳しい結果を取れないときは安全側（危険信号）', /危険:Hugging Face の自動検査で「危険」と判定/.test(T(r)), T(r));
  r = H(base({ readme: 'Download the zip below. Archive password: 1234' }));
  check('README の危険な言い回しは Hugging Face でも危険信号', /危険:パスワード付きの圧縮ファイル/.test(T(r)), T(r));
  r = H(base({ kind: 'space', files: ['README.md', 'app.py', 'model.pkl'] }));
  check('Space は pickle の注意を出さず、入力内容の注意を出す', !/pickle/.test(T(r)) && /参考:ブラウザで動くデモ画面/.test(T(r)), T(r));
  r = H(base({ kind: 'dataset', files: ['README.md', 'squad.py'] }));
  check('読み込み用の Python があるデータセット → 注意', /注意:読み込み用の Python ファイル/.test(T(r)), T(r));
}

// ---------- ライセンス判定 ----------
{
  const li = (id, name) => ctx.licenseInfo(id ? { spdx_id: id, name: name || id } : null);
  const is = (id, cls, marks, name) => { const r = li(id, name); check(`ライセンス ${id || '(なし)'} → ${cls} ${marks}`, r.cls === cls && r.marks.join(',') === marks, `${r.cls} ${r.marks} ${r.head}`); };
  is('MIT', 'v-ok', 'ok,ok,ok');
  is('apache-2.0', 'v-ok', 'ok,ok,ok');
  is('NCSA', 'v-ok', 'ok,ok,ok', 'University of Illinois/NCSA Open Source License');
  is('BSD-3-Clause', 'v-ok', 'ok,ok,ok');
  is('Unlicense', 'v-ok', 'ok,ok,ok');
  check('Unlicense・CC0 に「同梱が必要」と出さない', li('Unlicense').duties.length === 0 && li('cc0-1.0').duties.length === 0);
  is('MPL-2.0', 'v-warn', 'ok,cond,cond');
  is('LGPL-2.1', 'v-warn', 'ok,cond,cond');
  is('GPL-3.0', 'v-warn', 'cond,cond,cond');
  is('AGPL-3.0', 'v-ng', 'cond,cond,cond');
  is('cc-by-4.0', 'v-ok', 'ok,ok,ok');
  is('cc-by-sa-4.0', 'v-warn', 'ok,cond,cond');
  is('cc-by-nd-4.0', 'v-warn', 'ok,ng,cond');
  is('cc-by-nc-4.0', 'v-ng', 'ng,cond,cond');
  is('cc-by-nc-nd-4.0', 'v-ng', 'ng,ng,cond');
  is('creativeml-openrail-m', 'v-warn', 'cond,cond,cond');
  is('openrail++', 'v-warn', 'cond,cond,cond');
  is('llama3.2', 'v-warn', 'cond,cond,cond');
  is('NOASSERTION', 'v-warn', 'unknown,unknown,unknown', 'Other');
  is('other', 'v-warn', 'unknown,unknown,unknown', 'other');
  check('判別できないライセンスを「無い」と言わない', !/見つかりません/.test(li('NOASSERTION', 'Other').name), li('NOASSERTION', 'Other').name);
  is('', 'v-ng', 'ng,ng,ng');
  is('some-strange-license', 'v-warn', 'unknown,unknown,unknown');
  check('Hugging Face の短い名前は読みやすい名前にする', li('apache-2.0').name === 'Apache License 2.0', li('apache-2.0').name);
  const box = ctx.licenseBox(li('MIT', '<img src=x onerror=alert(1)>'), 'javascript:alert(1)', true);
  check('ライセンス欄：名前はエスケープし、https 以外のリンクは出さない', !box.includes('<img') && !box.includes('javascript:'), box.slice(0, 200));
}

// ---- 公開ページの安全設定：アクセス解析が止められていないか ----
{
  const csp = fs.readFileSync(path.join(ROOT, 'web/_headers'), 'utf8').match(/^\s*Content-Security-Policy:(.*)$/m)[1];
  const rule = name => (csp.split(';').map(s => s.trim().split(/\s+/)).find(a => a[0] === name) || []).slice(1);
  check('安全設定：解析の記録を自分のサイトへ送れる', rule('connect-src').includes("'self'"), rule('connect-src').join(' '));
  check('安全設定：解析のプログラムを読み込める', rule('script-src').includes('https://static.cloudflareinsights.com'), rule('script-src').join(' '));
}

console.log(`\n部品テスト：${pass} 件成功／${fail} 件失敗`);
process.exit(fail ? 1 : 0);
