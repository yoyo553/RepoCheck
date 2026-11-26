// RepoCheck — Macアプリ版の本体
// アプリの中に同梱した index.html を、Mac標準のWebKit（Safariと同じ表示エンジン）で表示するだけの入れ物。
// 判定の中身はすべて index.html 側にある。HTMLを直したら「アプリを作り直す.command」で反映する。

import Cocoa
import WebKit

// Mac の言語設定が日本語なら日本語、それ以外は英語で表示する（画面の中の HTML も同じ設定を見て切り替わる）
let isJapanese: Bool = (Locale.preferredLanguages.first ?? "ja").hasPrefix("ja")
func L(_ ja: String, _ en: String) -> String { isJapanese ? ja : en }

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
    var window: NSWindow!
    var web: WKWebView!

    // 動作確認用：`RepoCheck --selftest owner/repo` で起動すると、診断を1回実行して結果を表示し、終了する
    let selftestRepo: String? = {
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--selftest"), i + 1 < args.count { return args[i + 1] }
        return nil
    }()

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMenu()

        let config = WKWebViewConfiguration()
        // HTML側の「コピー」ボタンから、Macのクリップボードに書き込むための橋渡し
        config.userContentController.add(self, name: "copy")
        var bridge = "window.__nativeCopy = function(t){ window.webkit.messageHandlers.copy.postMessage(String(t)); };"
        // GitHub のトークンを画面に渡す（問い合わせ上限が1時間60回→5,000回になる）。メモリの中だけで、ファイルには書かない
        if let token = githubToken() {
            bridge += " window.__ghToken = \"\(token)\";"
        }
        config.userContentController.addUserScript(
            WKUserScript(source: bridge, injectionTime: .atDocumentStart, forMainFrameOnly: true))

        web = WKWebView(frame: .zero, configuration: config)
        web.navigationDelegate = self
        web.uiDelegate = self

        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 880),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered, defer: false)
        window.title = "RepoCheck"
        window.minSize = NSSize(width: 520, height: 500)
        window.center()
        window.setFrameAutosaveName("RepoCheckMainWindow")   // 前回のウインドウの位置と大きさを覚える
        window.contentView = web

        guard let page = Bundle.main.url(forResource: "index", withExtension: "html") else {
            fail(L("アプリの中に index.html が見つかりません。「アプリを作り直す.command」を実行してください。", "index.html is missing from the app. Run “アプリを作り直す.command” to rebuild it."))
            return
        }
        web.loadFileURL(page, allowingReadAccessTo: page.deletingLastPathComponent())

        if selftestRepo == nil {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    // MARK: - 画面の読み込み

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard let repo = selftestRepo else { return }
        runSelftest(repo)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        fail(L("画面の読み込みに失敗しました：", "Failed to load the page: ") + error.localizedDescription)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        fail(L("画面の読み込みに失敗しました：", "Failed to load the page: ") + error.localizedDescription)
    }

    // GitHub などへのリンクは、アプリ内ではなく普段使っているブラウザで開く
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if let url = action.request.url, let scheme = url.scheme,
           scheme == "http" || scheme == "https", action.navigationType == .linkActivated {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    // target="_blank" のリンク（新しいタブで開くリンク）もブラウザで開く
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = action.request.url { NSWorkspace.shared.open(url) }
        return nil
    }

    // MARK: - クリップボード

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "copy", let text = message.body as? String else { return }
        let pb = NSPasteboard.general
        pb.clearContents()
        if !pb.setString(text, forType: .string) {
            NSLog("RepoCheck: クリップボードへの書き込みに失敗しました")
        }
    }

    // MARK: - GitHub のトークン

    /// 環境変数 GITHUB_TOKEN / GH_TOKEN、なければ `gh auth token`（GitHub公式コマンドのログイン）から取る。
    /// Finder から起動したアプリには PATH が通っていないので、gh はよくある場所を直接探す。
    /// 英数字と _ 以外を含む値は、画面のスクリプトに埋め込むと危ないので使わない。
    private func githubToken() -> String? {
        let env = ProcessInfo.processInfo.environment
        var candidates = [env["GITHUB_TOKEN"], env["GH_TOKEN"]].compactMap { $0 }
        for path in ["/opt/homebrew/bin/gh", "/usr/local/bin/gh"] where FileManager.default.isExecutableFile(atPath: path) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: path)
            p.arguments = ["auth", "token"]
            let out = Pipe()
            p.standardOutput = out
            p.standardError = Pipe()
            do {
                try p.run()
                p.waitUntilExit()
                if p.terminationStatus == 0,
                   let s = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) {
                    candidates.append(s.trimmingCharacters(in: .whitespacesAndNewlines))
                }
            } catch {
                NSLog("RepoCheck: gh からトークンを取れませんでした：\(error.localizedDescription)")
            }
            break
        }
        let safe = candidates.first { t in
            !t.isEmpty && t.count <= 255 && t.unicodeScalars.allSatisfy {
                CharacterSet.alphanumerics.contains($0) && $0.isASCII || $0 == "_"
            }
        }
        return safe
    }

    // MARK: - 動作確認

    private func runSelftest(_ repo: String) {
        let js = """
        document.getElementById('url').value = repo;
        document.getElementById('go').click();
        await new Promise(r => setTimeout(r, 500));
        for (let i = 0; i < 200 && document.getElementById('go').disabled; i++) {
          await new Promise(r => setTimeout(r, 300));
        }
        const box = [...document.querySelectorAll('#out .box')].find(b => b.innerText.startsWith('🛡'));
        const sigs = box ? [...box.querySelectorAll('.sig')].map(s => s.classList[1] + '：' + s.querySelector('b').innerText) : [];
        const dep = box ? (box.innerText.split('📦')[1] || '').split('\\n').slice(0, 3).join(' ') : '';
        return [
          '状態表示：' + document.getElementById('status').textContent,
          '判定：' + (box ? box.querySelector('.verdict').innerText : '（安全性の欄なし）'),
          ...sigs,
          '依存ライブラリ：' + dep,
          '欄の数：' + document.querySelectorAll('#out .box').length,
          '訳の読み込み：' + (window.I18N ? Object.keys(window.I18N).join(',') : 'なし')
        ].join('\\n');
        """
        web.callAsyncJavaScript(js, arguments: ["repo": repo], in: nil, in: .page) { result in
            switch result {
            case .success(let value):
                print(value as? String ?? "（結果なし）")
                exit(0)
            case .failure(let error):
                print("動作確認に失敗しました：\(error)")
                exit(1)
            }
        }
    }

    // MARK: - メニュー（これが無いと、入力欄で ⌘V の貼り付けができない）

    private func setupMenu() {
        let main = NSMenu()

        let appItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: L("RepoCheck について", "About RepoCheck"), action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: L("RepoCheck を隠す", "Hide RepoCheck"), action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: L("RepoCheck を終了", "Quit RepoCheck"), action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        main.addItem(appItem)

        let editItem = NSMenuItem()
        let editMenu = NSMenu(title: L("編集", "Edit"))
        editMenu.addItem(withTitle: L("取り消す", "Undo"), action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: L("やり直す", "Redo"), action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: L("カット", "Cut"), action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: L("コピー", "Copy"), action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: L("ペースト", "Paste"), action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: L("すべてを選択", "Select All"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        main.addItem(editItem)

        let viewItem = NSMenuItem()
        let viewMenu = NSMenu(title: L("表示", "View"))
        viewMenu.addItem(withTitle: L("最初の画面に戻す", "Reload"), action: #selector(reloadPage), keyEquivalent: "r")
        viewItem.submenu = viewMenu
        main.addItem(viewItem)

        let windowItem = NSMenuItem()
        let windowMenu = NSMenu(title: L("ウインドウ", "Window"))
        windowMenu.addItem(withTitle: L("しまう", "Minimize"), action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: L("閉じる", "Close"), action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        windowItem.submenu = windowMenu
        main.addItem(windowItem)
        NSApp.windowsMenu = windowMenu

        NSApp.mainMenu = main
    }

    @objc private func reloadPage() { web.reload() }

    private func fail(_ message: String) {
        if selftestRepo != nil {
            print(message)
            exit(1)
        }
        let alert = NSAlert()
        alert.messageText = "RepoCheck"
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.runModal()
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
