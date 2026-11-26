#!/bin/bash
# 「RepoCheck.app」を組み立てて ~/Applications に置く。
# index.html や mac/main.swift を書き換えたときは、これをダブルクリックして反映する。
#
# 【なぜアプリをデスクトップ配下に置かないのか】
# macOSは、アプリからデスクトップ配下のファイルを読むことを制限している（TCCという保護機能）。
# 画面のHTMLはアプリの中に同梱し、アプリ本体はホームの「アプリケーション」フォルダに置く。
set -e
cd "$(dirname "$0")"
SRC="$(pwd)"
APP_NAME="RepoCheck"
BUILD="$SRC/build"
APP="$BUILD/$APP_NAME.app"
DEST_DIR="$HOME/Applications"
DEST="$DEST_DIR/$APP_NAME.app"

echo "① 作業用フォルダを準備しています…"
rm -rf "$APP" "$BUILD/icon.iconset"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$BUILD/icon.iconset"

echo "② プログラムを組み立てています（数十秒かかります）…"
xcrun swiftc -O -target arm64-apple-macos12.0 \
  -framework Cocoa -framework WebKit \
  -o "$APP/Contents/MacOS/$APP_NAME" "$SRC/mac/main.swift"

echo "③ 画面（index.html と訳の i18n.js）を同梱しています…"
cp "$SRC/index.html" "$APP/Contents/Resources/index.html"
cp "$SRC/i18n.js" "$APP/Contents/Resources/i18n.js"

echo "④ アイコンを作っています…"
xcrun swift "$SRC/mac/icon.swift" "$BUILD/icon_1024.png"
for s in 16 32 128 256 512; do
  sips -z $s $s "$BUILD/icon_1024.png" --out "$BUILD/icon.iconset/icon_${s}x${s}.png" >/dev/null
  d=$((s*2))
  sips -z $d $d "$BUILD/icon_1024.png" --out "$BUILD/icon.iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$BUILD/icon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"

VERSION="1.0.$(git -C "$SRC" rev-list --count HEAD 2>/dev/null || echo 0)"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$APP_NAME</string>
  <key>CFBundleDisplayName</key><string>$APP_NAME</string>
  <key>CFBundleExecutable</key><string>$APP_NAME</string>
  <key>CFBundleIdentifier</key><string>info.youmix.repocheck</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleDevelopmentRegion</key><string>ja</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>RepoCheck</string>
</dict>
</plist>
PLIST

echo "⑤ 署名しています（自分のMacで動かすための簡易署名）…"
codesign --force --deep --sign - "$APP"

echo "⑥ アプリケーションフォルダに置いています…"
mkdir -p "$DEST_DIR"
rm -rf "$DEST"
cp -R "$APP" "$DEST"
# Launchpad や Spotlight にすぐ出るよう、場所を登録し直す
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$DEST" >/dev/null 2>&1 || true

echo ""
echo "✅ 完成しました：$DEST（バージョン $VERSION）"
echo "   Spotlight（⌘＋スペース）で「RepoCheck」と打つか、Finder の「アプリケーション」から開けます。"
