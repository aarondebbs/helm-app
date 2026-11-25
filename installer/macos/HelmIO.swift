// HelmIO: screen capture and input injection for Helm's remote screen on macOS. It is started by `helm-agent helper`
// (running as the signed-in user) and talks over stdin/stdout, never the network.
//
//   stdin  (one command per line)
//     chk                        report whether Screen Recording and Accessibility are allowed
//     cap <maxWidth>             capture the main display, scaled down to at most maxWidth pixels wide
//     mm <fx> <fy>               move the pointer (fx, fy are fractions 0...1 of the display)
//     md|mu <fx> <fy> <b>        mouse button down / up (0 left, 1 middle, 2 right)
//     wh <dx> <dy>               scroll
//     kd|ku <keycode> <flags>    key down / up (macOS virtual key code, CGEventFlags)
//     txt <hex>                  type text (UTF-8 as hex)
//   stdout (binary)
//     'F' u32 w u32 h <w*h*4 bytes BGRA>     a frame
//     'C' <screen 0/1> <accessibility 0/1>   answer to chk
//     'E' u32 len <text>                      an error
import Cocoa
import CoreGraphics

let outH = FileHandle.standardOutput
func be32(_ v: Int) -> Data { var b = UInt32(v).bigEndian; return Data(bytes: &b, count: 4) }
func sendErr(_ s: String) { let d = Data(s.utf8); outH.write(Data([0x45]) + be32(d.count) + d) }

var held = [false, false, false]

func screenAllowed() -> Bool { return CGPreflightScreenCaptureAccess() }

// CGDisplayCreateImage is marked unavailable in the newest SDKs, but is still present at run time. Look it up by name
// so the program compiles everywhere, and fall back to the screencapture tool if it is missing or returns nothing.
typealias DisplayImageFn = @convention(c) (CGDirectDisplayID) -> Unmanaged<CGImage>?
func grabImage() -> CGImage? {
    if let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "CGDisplayCreateImage") {
        let fn = unsafeBitCast(sym, to: DisplayImageFn.self)
        if let img = fn(CGMainDisplayID())?.takeRetainedValue() { return img }
    }
    let tmp = NSTemporaryDirectory() + "helm-cap-\(getpid()).png"
    defer { try? FileManager.default.removeItem(atPath: tmp) }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
    p.arguments = ["-x", "-t", "png", tmp]
    do { try p.run(); p.waitUntilExit() } catch { return nil }
    guard let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: tmp) as CFURL, nil) else { return nil }
    return CGImageSourceCreateImageAtIndex(src, 0, nil)
}

func capture(maxW: Int) {
    if !screenAllowed() {
        _ = CGRequestScreenCaptureAccess()
        sendErr("Screen Recording is not allowed for Helm on this Mac. Open System Settings, then Privacy & Security, then Screen Recording, turn on Helm, and start the session again.")
        return
    }
    guard let img = grabImage() else { sendErr("The screen could not be captured."); return }
    var w = img.width, h = img.height
    if maxW > 0 && w > maxW { h = max(1, h * maxW / w); w = maxW }
    let info = CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue
    guard let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                              space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: info) else { sendErr("No drawing surface."); return }
    ctx.interpolationQuality = .medium
    ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
    guard let p = ctx.data else { sendErr("No pixels."); return }
    outH.write(Data([0x46]) + be32(w) + be32(h) + Data(bytes: p, count: w * h * 4))
}

func point(_ fx: Double, _ fy: Double) -> CGPoint {
    let b = CGDisplayBounds(CGMainDisplayID())
    return CGPoint(x: b.minX + min(max(fx, 0), 1) * (b.width - 1), y: b.minY + min(max(fy, 0), 1) * (b.height - 1))
}

func post(_ e: CGEvent?) { e?.post(tap: .cghidEventTap) }

func mouse(_ kind: String, _ fx: Double, _ fy: Double, _ b: Int) {
    let p = point(fx, fy)
    let btn: CGMouseButton = b == 2 ? .right : (b == 1 ? .center : .left)
    var et: CGEventType
    switch kind {
    case "md": held[min(max(b, 0), 2)] = true
        et = b == 2 ? .rightMouseDown : (b == 1 ? .otherMouseDown : .leftMouseDown)
    case "mu": held[min(max(b, 0), 2)] = false
        et = b == 2 ? .rightMouseUp : (b == 1 ? .otherMouseUp : .leftMouseUp)
    default:
        et = held[0] ? .leftMouseDragged : (held[2] ? .rightMouseDragged : (held[1] ? .otherMouseDragged : .mouseMoved))
    }
    let e = CGEvent(mouseEventSource: nil, mouseType: et, mouseCursorPosition: p, mouseButton: btn)
    if kind != "mm" { e?.setIntegerValueField(.mouseEventClickState, value: 1) }
    post(e)
}

func scroll(_ dx: Double, _ dy: Double) {
    post(CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 2,
                 wheel1: Int32(max(-2000, min(2000, -dy))), wheel2: Int32(max(-2000, min(2000, -dx))), wheel3: 0))
}

func key(_ code: Int, _ flags: UInt64, down: Bool) {
    let e = CGEvent(keyboardEventSource: nil, virtualKey: CGKeyCode(code), keyDown: down)
    e?.flags = CGEventFlags(rawValue: flags)
    post(e)
}

func typeText(_ s: String) {
    var u = Array(s.utf16)
    for down in [true, false] {
        let e = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: down)
        e?.keyboardSetUnicodeString(stringLength: u.count, unicodeString: &u)
        post(e)
    }
}

func fromHex(_ s: String) -> String {
    var bytes = [UInt8](); var i = s.startIndex
    while i < s.endIndex, let j = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
        if let b = UInt8(s[i..<j], radix: 16) { bytes.append(b) }
        i = j
    }
    return String(decoding: bytes, as: UTF8.self)
}

let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: false] as CFDictionary
while let line = readLine() {
    let f = line.split(separator: " ").map(String.init)
    guard let c = f.first else { continue }
    func d(_ i: Int) -> Double { return i < f.count ? Double(f[i]) ?? 0 : 0 }
    switch c {
    case "chk":
        let ax = AXIsProcessTrustedWithOptions(opts)
        if !ax { _ = AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary) }
        outH.write(Data([0x43, screenAllowed() ? 1 : 0, ax ? 1 : 0]))
    case "cap": capture(maxW: Int(d(1)))
    case "mm": mouse("mm", d(1), d(2), 0)
    case "md", "mu": mouse(c, d(1), d(2), Int(d(3)))
    case "wh": scroll(d(1), d(2))
    case "kd", "ku": key(Int(d(1)), UInt64(d(2)), down: c == "kd")
    case "txt": if f.count > 1 { typeText(fromHex(f[1])) }
    default: break
    }
}
