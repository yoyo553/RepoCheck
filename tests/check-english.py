# 英語表示の結果に、日本語の文言が残っていないかを調べる（node tests/harness.mjs --lang en --dump tests/after-en.json のあとに実行）
# 元のデータ（リポジトリの説明文・ファイル名・脆弱性の概要・作者名など）に含まれる日本語は対象外にする
import json, re, sys
JP = re.compile(r'[぀-ヿ㐀-鿿！-～「」、。]')
d = json.load(open(sys.argv[1] if len(sys.argv) > 1 else 'tests/after-en.json'))
def strip_data(h):
    h = re.sub(r'<code>.*?</code>', '', h, flags=re.S)           # ファイル名・コマンド・ライブラリ名
    h = re.sub(r'<pre>.*?</pre>', '', h, flags=re.S)
    h = re.sub(r'<p class="desc">.*?</p>', '', h, flags=re.S)    # リポジトリの説明文
    h = re.sub(r'<p class="name">.*?</p>', '', h, flags=re.S)
    h = re.sub(r'<div style="font-size:12px;color:var\(--muted\)">・.*?</div>', '', h, flags=re.S)  # 脆弱性の概要
    h = re.sub(r'<li>(Critical|High|Medium|Low|Unknown): .*?</li>', '', h, flags=re.S)             # GitHub の脆弱性の概要
    h = re.sub(r'data-cmd="[^"]*"', '', h)
    h = re.sub(r'“[^”]*”', '', h)                                   # 作者名・リポジトリ名
    h = re.sub(r'<span class="langlist">.*?</span>', '', h, flags=re.S)
    return h
bad = 0
for repo, r in d['repos'].items():
    for where, text in (('画面', strip_data(r['html'])), ('状態表示', r['status'])):
        for m in JP.finditer(text):
            bad += 1
            if bad <= 15: print(f'{repo}（{where}）: …{text[max(0,m.start()-60):m.end()+40]}…')
            break
for name, sec in d['fixtures'].items():
    for k in ('danger', 'warn', 'info', 'good'):
        for s in sec[k]:
            t = strip_data(s['t'] + ' ' + s['x'])
            if JP.search(t):
                bad += 1
                if bad <= 15: print(f'架空データ「{name}」: {t[:150]}')
print('日本語が残っていた箇所:', bad)
sys.exit(1 if bad else 0)
