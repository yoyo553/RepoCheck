#!/bin/bash
# RepoCheck を https://repocheck.youmix.info に公開する（index.html を直したら、これをダブルクリック）
# トークンは Mac のキーチェーンから読む（名前は repocheck-cloudflare）
set -e
cd "$(dirname "$0")"
SRC="$(pwd)"
OUT="$SRC/deploy/public"

echo "① 公開するファイルを集めています…"
rm -rf "$OUT"; mkdir -p "$OUT"
cp "$SRC/index.html" "$SRC/i18n.js" "$SRC/badge.svg" "$SRC/web/_headers" "$SRC/web/robots.txt" "$SRC/web/404.html" "$SRC/web/privacy.html" "$OUT/"
# ツールごとの診断結果ページ（pages/build.mjs で作ったもの。作り直すと日付と結果が新しくなる）
# サイトマップのアドレスは .html を外した形（Cloudflare が .html 付きを .html なしへ 307 転送するため）
cp -R "$SRC/web/r" "$OUT/r"
xcrun swift "$SRC/web/og.swift" "$OUT/og.png"
xcrun swift "$SRC/mac/icon.swift" "$OUT/icon_1024.png"
sips -z 256 256 "$OUT/icon_1024.png" --out "$OUT/favicon.png" >/dev/null && rm "$OUT/icon_1024.png"
cat > "$OUT/sitemap.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://repocheck.youmix.info/</loc><lastmod>$(date +%F)</lastmod></url>
  <url><loc>https://repocheck.youmix.info/privacy</loc><lastmod>$(date +%F)</lastmod></url>
$(for f in "$SRC"/web/r/*.html; do echo "  <url><loc>https://repocheck.youmix.info/r/$(basename "$f" .html)</loc><lastmod>$(date -r "$f" +%F)</lastmod></url>"; done)
</urlset>
XML

echo "② Cloudflare に公開しています…"
TOKEN="$(security find-generic-password -s repocheck-cloudflare -a deploy -w 2>/dev/null || true)"
if [ -z "$TOKEN" ]; then echo "❌ キーチェーンにトークンがありません（repocheck-cloudflare）"; exit 1; fi
cd "$SRC/deploy"
CLOUDFLARE_API_TOKEN="$TOKEN" npx --yes wrangler@latest deploy

echo ""
echo "✅ 公開しました：https://repocheck.youmix.info/"
