# i18n/*.txt（番号<TAB>訳）と i18n/keys.json（番号→英文）から ../i18n.js を作る
# 使い方：python3 i18n/build.py
# 英文の一覧（keys.json）は index.html から抜き出したもの。文を足したら keys.json にも足して番号を振る
import json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
K = json.load(open(os.path.join(HERE, 'keys.json'), encoding='utf8'))
def norm_html(s):  # index.html の normHTML() と同じ
    return re.sub(r'\s+', ' ', re.sub(r'</?tbody>', '', s).replace('&amp;', '&')).strip()
def key(id):
    if id.startswith('#'): return id
    if id.startswith('H'): return norm_html(K['html'][int(id[1:])])
    return K['keys'][int(id)]
out, bad = {}, 0
for lang in ['zh-CN', 'zh-TW', 'ko']:
    f = os.path.join(HERE, lang + '.txt')
    if not os.path.exists(f): continue
    d = {}
    for n, line in enumerate(open(f, encoding='utf8'), 1):
        line = line.rstrip('\n')
        if not line.strip(): continue
        id, _, text = line.partition('\t')
        text = text.replace('\\n', '\n')
        en = key(id)
        # 差し込み位置 {0} {n} が英文にあるものだけか確かめる（訳で省くのは可）
        for ph in re.findall(r'\{\w+\}', text):
            if ph not in en and not (id.startswith('#') and ph == '{n}'):
                print(f'{lang}.txt {n}行目：英文に無い {ph}'); bad += 1
        for ph in re.findall(r'\{\d+\}', en):
            if ph not in text and lang and id not in ('228', '231'):
                print(f'{lang}.txt {n}行目：{ph} が訳に無い（意図的なら無視）')
        d[en] = text
    out[lang] = d
js = ('// RepoCheck の中国語（簡体字・繁体字）・韓国語の訳。i18n/build.py が作るので直接は書き換えない\n'
      '// 鍵は index.html の英文（L の2つ目・LT のひな形）。{0} などは差し込む値。\'#days\' は plural() 用で {n} が数\n'
      'window.I18N=' + json.dumps(out, ensure_ascii=False, indent=0) + ';\n')
open(os.path.join(HERE, '..', 'i18n.js'), 'w', encoding='utf8').write(js)
print({k: len(v) for k, v in out.items()}, '件を書き出しました')
sys.exit(1 if bad else 0)
