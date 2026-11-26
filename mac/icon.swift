// RepoCheck のアイコンを描いて PNG に書き出す（1024×1024）
// 使い方：swift icon.swift 出力先.png
// 絵柄：紺の角丸の地に、白い盾と、盾の中のチェックマーク

import Cocoa

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon_1024.png"
let size: CGFloat = 1024

guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size),
                                 bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                 colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
      let ctx = NSGraphicsContext(bitmapImageRep: rep) else {
    print("アイコン用の画像を用意できませんでした")
    exit(1)
}
NSGraphicsContext.current = ctx

// 地：macOSのアイコンの決まりに合わせ、四辺に余白を取った角丸四角
let inset: CGFloat = 100
let body = NSRect(x: inset, y: inset, width: size - inset * 2, height: size - inset * 2)
let bg = NSBezierPath(roundedRect: body, xRadius: 185, yRadius: 185)
NSGradient(starting: NSColor(calibratedRed: 0.16, green: 0.28, blue: 0.50, alpha: 1),
           ending: NSColor(calibratedRed: 0.07, green: 0.12, blue: 0.24, alpha: 1))!
    .draw(in: bg, angle: -90)

// 盾
let cx = size / 2
let shield = NSBezierPath()
shield.move(to: NSPoint(x: cx, y: 790))
shield.curve(to: NSPoint(x: 300, y: 690), controlPoint1: NSPoint(x: 440, y: 745), controlPoint2: NSPoint(x: 360, y: 720))
shield.line(to: NSPoint(x: 300, y: 520))
shield.curve(to: NSPoint(x: cx, y: 225), controlPoint1: NSPoint(x: 300, y: 380), controlPoint2: NSPoint(x: 400, y: 285))
shield.curve(to: NSPoint(x: 724, y: 520), controlPoint1: NSPoint(x: 624, y: 285), controlPoint2: NSPoint(x: 724, y: 380))
shield.line(to: NSPoint(x: 724, y: 690))
shield.curve(to: NSPoint(x: cx, y: 790), controlPoint1: NSPoint(x: 664, y: 720), controlPoint2: NSPoint(x: 584, y: 745))
shield.close()
NSColor(calibratedWhite: 1, alpha: 0.96).setFill()
shield.fill()

// チェックマーク（アクセントの青）
let check = NSBezierPath()
check.move(to: NSPoint(x: 395, y: 515))
check.line(to: NSPoint(x: 480, y: 430))
check.line(to: NSPoint(x: 640, y: 610))
check.lineWidth = 62
check.lineCapStyle = .round
check.lineJoinStyle = .round
NSColor(calibratedRed: 0.35, green: 0.63, blue: 0.95, alpha: 1).setStroke()
check.stroke()

NSGraphicsContext.current = nil
guard let png = rep.representation(using: .png, properties: [:]) else {
    print("PNGに変換できませんでした")
    exit(1)
}
do {
    try png.write(to: URL(fileURLWithPath: out))
} catch {
    print("アイコンを書き出せませんでした：\(error.localizedDescription)")
    exit(1)
}
