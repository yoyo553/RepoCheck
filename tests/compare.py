# 2つの全結果（--dump の出力）を比べ、違いを表示する。書き換えで判定が変わっていないかの確認用
# 使い方: python3 tests/compare.py 前.json 後.json
import json, sys
a = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
diffs = 0
def show(label, x, y):
    global diffs
    diffs += 1
    if diffs <= 5:
        x = json.dumps(x, ensure_ascii=False, sort_keys=True); y = json.dumps(y, ensure_ascii=False, sort_keys=True)
        i = next((i for i in range(min(len(x), len(y))) if x[i] != y[i]), min(len(x), len(y)))
        print(f'違い: {label}\n  前: …{x[max(0,i-80):i+120]}\n  後: …{y[max(0,i-80):i+120]}')
for k in a['repos']:
    if k not in b['repos']: show(k + '（後に無い）', '', ''); continue
    for part in ('sec', 'html', 'status'):
        if a['repos'][k].get(part) != b['repos'][k].get(part): show(k + ' の ' + part, a['repos'][k].get(part), b['repos'][k].get(part))
for k in a['fixtures']:
    if a['fixtures'][k] != b['fixtures'].get(k): show('架空データ ' + k, a['fixtures'][k], b['fixtures'].get(k))
print(f"比べた数：リポジトリ {len(a['repos'])} 個・架空データ {len(a['fixtures'])} 件／違い {diffs} 件")
sys.exit(1 if diffs else 0)
