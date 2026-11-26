// SNS で共有したときに出る画像（1200×630）を描いて PNG に書き出す
// 使い方：swift og.swift 出力先.png
// 絵柄：紺の地の左に白い盾とチェック（アプリのアイコンと同じ形）、右に名前と説明

import Cocoa

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "og.png"
let W: CGFloat = 1200, H: CGFloat = 630

guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(W), pixelsHigh: Int(H),
                                 bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                 colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
      let ctx = NSGraphicsContext(bitmapImageRep: rep) else {
    print("画像を用意できませんでした")
    exit(1)
}
NSGraphicsContext.current = ctx

// 地
NSGradient(starting: NSColor(calibratedRed: 0.16, green: 0.28, blue: 0.50, alpha: 1),
           ending: NSColor(calibratedRed: 0.07, green: 0.12, blue: 0.24, alpha: 1))!
    .draw(in: NSRect(x: 0, y: 0, width: W, height: H), angle: -90)

// 盾（アイコンの盾を、中心 (250, 315)・0.62 倍で描く）
let s: CGFloat = 0.62, ox: CGFloat = 250 - 512 * s, oy: CGFloat = 315 - 507 * s
func P(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: ox + x * s, y: oy + y * s) }
let shield = NSBezierPath()
shield.move(to: P(512, 790))
shield.curve(to: P(300, 690), controlPoint1: P(440, 745), controlPoint2: P(360, 720))
shield.line(to: P(300, 520))
shield.curve(to: P(512, 225), controlPoint1: P(300, 380), controlPoint2: P(400, 285))
shield.curve(to: P(724, 520), controlPoint1: P(624, 285), controlPoint2: P(724, 380))
shield.line(to: P(724, 690))
shield.curve(to: P(512, 790), controlPoint1: P(664, 720), controlPoint2: P(584, 745))
shield.close()
NSColor(calibratedWhite: 1, alpha: 0.96).setFill()
shield.fill()
let check = NSBezierPath()
check.move(to: P(395, 515)); check.line(to: P(480, 430)); check.line(to: P(640, 610))
check.lineWidth = 62 * s
check.lineCapStyle = .round; check.lineJoinStyle = .round
let blue = NSColor(calibratedRed: 0.35, green: 0.63, blue: 0.95, alpha: 1)
blue.setStroke()
check.stroke()

// 文字
func draw(_ text: String, size: CGFloat, weight: NSFont.Weight, color: NSColor, at p: NSPoint) {
    let font = NSFont(name: weight == .bold ? "HiraginoSans-W7" : "HiraginoSans-W4", size: size)
        ?? NSFont.systemFont(ofSize: size, weight: weight)
    (text as NSString).draw(at: p, withAttributes: [.font: font, .foregroundColor: color])
}
let white = NSColor.white, soft = NSColor(calibratedRed: 0.80, green: 0.87, blue: 0.97, alpha: 1)
draw("RepoCheck", size: 92, weight: .bold, color: white, at: NSPoint(x: 470, y: 400))
draw("GitHub・Hugging Face の", size: 44, weight: .bold, color: white, at: NSPoint(x: 474, y: 318))
draw("安全性チェック", size: 44, weight: .bold, color: white, at: NSPoint(x: 474, y: 258))
draw("URL を貼るだけで、ウイルス配布・なりすまし・", size: 27, weight: .regular, color: soft, at: NSPoint(x: 476, y: 178))
draw("脆弱性・ライセンスを日本語で判定。無料・登録不要", size: 27, weight: .regular, color: soft, at: NSPoint(x: 476, y: 138))
draw("repocheck.youmix.info", size: 24, weight: .regular, color: blue, at: NSPoint(x: 476, y: 62))

NSGraphicsContext.current = nil
guard let png = rep.representation(using: .png, properties: [:]) else { print("PNGに変換できませんでした"); exit(1) }
do { try png.write(to: URL(fileURLWithPath: out)) } catch { print("書き出せませんでした：\(error.localizedDescription)"); exit(1) }
