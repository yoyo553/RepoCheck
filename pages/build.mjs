// よく調べられるツールの「診断結果ページ」を作る（検索から来る人の入口）
//   node pages/build.mjs           … pages/tools.json の全部を、いまの公開情報で診断し直して web/r/<slug>.html を作る
//   node pages/build.mjs --cache   … 診断し直さず、保存済みの通信（tests/cache）で作る（見た目だけ直したいとき）
// アドレスは .html を外した形（/r/uvr）で書く。Cloudflare の初期設定では /r/uvr.html → /r/uvr へ 307 転送されるため、
// canonical やサイトマップを .html 付きにすると「転送されるアドレス」を正式なアドレスとして伝えてしまう。
// 診断は tests/harness.mjs（本物の index.html の処理を Node.js で動かす検証台）に任せ、その画面の HTML を流し込む。
// あわせて index.html の <!--tools:start-->〜<!--tools:end--> の一覧も書き換える。
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..');
const OUT = path.join(ROOT, 'web', 'r');
const SITE = 'https://repocheck.youmix.info/';
const tools = JSON.parse(fs.readFileSync(path.join(HERE, 'tools.json'), 'utf8'));
const useCache = process.argv.includes('--cache');

// 名前の重複・形の確認
const slugs = new Set();
for (const t of tools) {
  if (!/^[a-z0-9-]+$/.test(t.slug)) throw new Error('slug は英小文字・数字・- だけ：' + t.slug);
  if (slugs.has(t.slug)) throw new Error('slug が重複：' + t.slug);
  slugs.add(t.slug);
}

// ① 診断（検証台を日本語で回し、画面の HTML を受け取る）
const dumpFile = path.join(os.tmpdir(), 'repocheck-pages-' + process.pid + '.json');
const args = ['tests/harness.mjs', '--no-report', '--dump', dumpFile, ...(useCache ? [] : ['--refresh']), ...tools.map((t) => t.url)];
try { execFileSync('node', args, { cwd: ROOT, stdio: ['ignore', 'ignore', 'inherit'] }); }
catch (e) { if (!fs.existsSync(dumpFile)) throw e; } // 架空データ側の失敗で終了コードが 1 でも、結果は使える
const dump = JSON.parse(fs.readFileSync(dumpFile, 'utf8'));
fs.unlinkSync(dumpFile);

// ② ページの部品
const indexHtml = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const css = indexHtml.match(/<style>([\s\S]*?)<\/style>/)[1];
const logo = indexHtml.match(/<div class="logo">[\s\S]*?<\/div>/)[0];
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const now = new Date();
const dateJa = `${now.getFullYear()}年${now.getMonth() + 1}月${now.getDate()}日`;
// 日付は日本時間で作る（toISOString は世界標準時なので、朝に作ると前の日になる）
const isoOf = (y, m, d) => `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
const dateIso = isoOf(now.getFullYear(), now.getMonth() + 1, now.getDate());
// --cache は診断し直さないので、診断日は前のページのものを引き継ぐ（古い結果に今日の日付を付けない）
function checkedDate(slug) {
  if (!useCache) return { ja: dateJa, iso: dateIso };
  let old = ''; try { old = fs.readFileSync(path.join(OUT, slug + '.html'), 'utf8'); } catch (e) { /* 初めて作るページ */ }
  const m = old.match(/診断日：((\d{4})年(\d{1,2})月(\d{1,2})日)/);
  if (!m) throw new Error(slug + '：前の診断日が分からないので --cache では作れません。--cache を外して実行してください');
  return { ja: m[1], iso: isoOf(m[2], m[3], m[4]) };
}

const toolList = (current) => '<ul class="toollist">' + tools.map((t) =>
  t.slug === current ? `<li><b>${esc(t.short)}</b></li>` : `<li><a href="/r/${t.slug}">${esc(t.short)}</a></li>`).join('') + '</ul>';

const promo = `<div class="box promo"><p class="promo-t">🎤 歌ってみた・音声 AI の MIX は YOUMIX へ</p>
<p>RepoCheck は、歌ってみたの MIX・マスタリングを請け負う <b>YOUMIX</b> が作っています。ボーカル分離や AI ボイスで作った音源の仕上げも、ご相談ください。</p>
<a class="promo-btn" href="https://youmix.info/order?utm_source=repocheck&amp;utm_medium=toolpage" target="_blank" rel="noopener">MIX の料金と依頼方法を見る →</a></div>`;

const problems = [];
let made = 0;
for (const t of tools) {
  const r = dump.repos[t.url];
  if (!r || !r.html || !r.sec) { problems.push(`${t.slug}：診断できなかった（${r ? r.status : '結果なし'}）`); continue; }
  // 結果の下の追加欄（バッジなど）は切り取る。このページには専用の案内を置く
  let result = r.html.split('<!--extras-->')[0];
  if (result === r.html) problems.push(`${t.slug}：<!--extras--> の目印が見つからない（index.html の extrasHTML を確認）`);
  const { danger, warn } = r.sec;
  const day = checkedDate(t.slug);
  const verdict = danger.length ? `危険信号が ${danger.length} 件見つかりました` : warn.length ? `危険信号は無く、注意点が ${warn.length} 件ありました` : '目立った危険信号は見つかりませんでした';
  const title = `${t.short} は安全？入れる前のチェック結果｜RepoCheck`;
  const desc = `${t.name} を RepoCheck で診断した結果（${day.ja}時点）：${verdict}。安全性・使い方・ライセンス・今も動きそうかをまとめています。`;
  // 同じサイトの中で開く（手元の確認でも本番に飛ばないように）
  const again = '/?url=' + encodeURIComponent(t.url);
  // 「UVR（…） は」のように、かっこの後ろに空白が入らないように
  const wa = /[）)]$/.test(t.name) ? 'は' : ' は';
  const page = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<link rel="canonical" href="${SITE}r/${t.slug}">
<link rel="icon" href="/favicon.png">
<meta property="og:type" content="article">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:url" content="${SITE}r/${t.slug}">
<meta property="og:image" content="${SITE}og.png">
<meta name="twitter:card" content="summary_large_image">
<script type="application/ld+json">${JSON.stringify({ '@context': 'https://schema.org', '@type': 'Article', headline: title, description: desc, dateModified: day.iso, author: { '@type': 'Organization', name: 'YOUMIX', url: 'https://youmix.info/' } }).replace(/</g, '\\u003c')}</script>
<style>${css}
  .page-h1{font-size:24px;margin:0 0 6px;line-height:1.45}
  .checked{color:var(--muted);font-size:13px;margin:0 0 14px}
  .intro{font-size:15px;margin:0 0 16px}
  .again{display:inline-block;background:linear-gradient(135deg,var(--cyan),var(--blue) 55%,var(--violet));color:#06101F;font-weight:800;font-size:15px;padding:13px 22px;border-radius:14px;text-decoration:none;margin:0 0 26px;box-shadow:0 10px 30px -8px rgba(90,160,242,.6);transition:transform .2s var(--ease)}
  .again:hover{transform:translateY(-2px);color:#06101F;text-decoration:none}
  .page-h1{font-size:clamp(24px,4.4vw,34px);color:#fff;text-wrap:balance}
  .toollist{display:flex;flex-wrap:wrap;gap:8px;list-style:none;padding:0;margin:8px 0 0}
  .toollist li{font-size:13px;border:1px solid var(--line);border-radius:999px;padding:4px 12px;background:var(--panel)}
  .toollist a{text-decoration:none}
  #out{display:block}
</style>
</head>
<body>
<div class="wrap">
  <header class="site"><a href="/" style="color:var(--text);text-decoration:none">${logo}</a><nav class="top"><a href="/">トップ</a><a href="/privacy">プライバシー</a></nav></header>
  <h1 class="page-h1">${esc(t.name)}${wa}安全？入れる前のチェック結果</h1>
  <p class="checked">診断日：${day.ja}（この日に公開されていた情報で判定しています。最新の結果は下のボタンから）</p>
  <p class="intro">${esc(t.intro)}</p>
  <a class="again" href="${esc(again)}">最新の情報でもう一度診断する →</a>
  <div id="out" class="show">${result}</div>
  ${promo}
  <div class="box"><h2>ほかのツールの診断結果</h2>${toolList(t.slug)}</div>
  <footer class="site">
    <div>RepoCheck — GitHub・Hugging Face の安全性チェック（無料・登録不要）</div>
    <div>運営：<a href="https://youmix.info/" target="_blank" rel="noopener">YOUMIX</a> ・ <a href="/privacy">プライバシーポリシー</a></div>
  </footer>
  <p class="disclaimer">※ この判定は、${day.ja}に公開されていた情報から危険の兆候を探した<b>目安</b>です。安全を保証するものではなく、見つけられない危険もあります。その後に内容が変わっていることもあるので、使う前に最新の情報で診断し直してください。ダウンロード・インストール・利用は、ご自身の判断と責任で行ってください。</p>
</div>
<script>
// コマンドのコピー（本体の index.html と同じ動き）
document.querySelectorAll('.copy').forEach(function(b){ b.addEventListener('click',function(){
  var t=b.getAttribute('data-cmd');
  var legacy=function(){return new Promise(function(ok,ng){var a=document.createElement('textarea');a.value=t;a.setAttribute('readonly','');a.style.position='fixed';a.style.opacity='0';document.body.appendChild(a);a.select();var d=false;try{d=document.execCommand('copy');}catch(e){}a.remove();d?ok():ng();});};
  var p=(navigator.clipboard&&navigator.clipboard.writeText)?navigator.clipboard.writeText(t).catch(legacy):legacy();
  if(b.dataset.orig===undefined) b.dataset.orig=b.textContent;
  p.then(function(){b.textContent='コピーしました ✓';},function(){b.textContent='コピーできませんでした。手で選んでコピーしてください';});
  clearTimeout(b._f); b._f=setTimeout(function(){b.textContent=b.dataset.orig;},1600);
});});
</script>
</body>
</html>
`;
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, t.slug + '.html'), page);
  made++;
  console.log(`✅ r/${t.slug}.html … ${verdict}`);
}

// 使われなくなった古いページを片付ける（tools.json から外したもの）
for (const f of fs.existsSync(OUT) ? fs.readdirSync(OUT) : []) {
  if (f.endsWith('.html') && !slugs.has(f.replace(/\.html$/, ''))) { fs.unlinkSync(path.join(OUT, f)); console.log('🗑 古いページを削除：r/' + f); }
}

// ③ index.html の一覧（日本語のときだけ見える）を書き換える
const START = '<!--tools:start-->', END = '<!--tools:end-->';
const a = indexHtml.indexOf(START), b = indexHtml.indexOf(END);
if (a < 0 || b < a) problems.push('index.html に <!--tools:start--> / <!--tools:end--> が無い');
else {
  // Mac アプリには専用ページが入っていないので、一覧は公開サイトだけで見せる（web-only）
  const block = START + '\n  <div class="seo web-only" data-l="ja">\n    <h2>よく調べられているツールの診断結果</h2>\n    '
    + toolList(null) + '\n  </div>\n  ' + END;
  fs.writeFileSync(path.join(ROOT, 'index.html'), indexHtml.slice(0, a) + block + indexHtml.slice(b + END.length));
}

console.log(`\n${made} / ${tools.length} ページを作りました`);
if (problems.length) { console.log('\n⚠ 問題：\n- ' + problems.join('\n- ')); process.exit(1); }
