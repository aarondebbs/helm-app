// Helm menu-bar app for macOS. It runs as the signed-in user, shows a small icon at the top of the screen and reads
// the status the Helm agent (a root daemon) writes to /Library/Application Support/Helm/public/status.json.
// It can open the chat window in the browser and send a support request through the agent's local endpoint.
import Cocoa

struct Status: Decodable {
    var state: String?
    var control: String?
    var chatToken: String?
    var org: String?
    var computer: String?
    var version: String?
    var allowSupport: Bool?
    var chatUnread: Int?
    var supportText: String?
}

final class App: NSObject, NSApplicationDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let path = "/Library/Application Support/Helm/public/status.json"
    var status = Status()
    var fresh = false

    func applicationDidFinishLaunching(_ n: Notification) {
        refresh()
        Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
    }

    func refresh() {
        fresh = false
        if let d = FileManager.default.contents(atPath: path),
           let s = try? JSONDecoder().decode(Status.self, from: d) {
            status = s
            if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
               let m = attrs[.modificationDate] as? Date { fresh = Date().timeIntervalSince(m) < 180 }
        }
        let state = fresh ? (status.state ?? "offline") : "stopped"
        let symbol: String
        switch state {
        case "connected": symbol = "checkmark.shield"
        case "pending", "connecting", "starting": symbol = "clock"
        default: symbol = "exclamationmark.triangle"
        }
        if let b = item.button {
            if #available(macOS 11.0, *), let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "Helm") {
                img.isTemplate = true
                b.image = img
                b.title = (status.chatUnread ?? 0) > 0 ? " \(status.chatUnread ?? 0)" : ""
            } else {
                b.title = "Helm"
            }
            b.toolTip = headline()
        }
        item.menu = buildMenu()
    }

    func headline() -> String {
        switch fresh ? (status.state ?? "offline") : "stopped" {
        case "connected": return "Connected and protected"
        case "pending": return "Waiting for approval"
        case "connecting", "starting": return "Connecting…"
        case "stopped": return "The Helm agent is not running"
        default: return "Offline: will reconnect on its own"
        }
    }

    func buildMenu() -> NSMenu {
        let m = NSMenu()
        let title = (status.org ?? "").isEmpty ? "Helm Agent" : "Helm · \(status.org ?? "")"
        let h = NSMenuItem(title: title, action: nil, keyEquivalent: ""); h.isEnabled = false; m.addItem(h)
        let s = NSMenuItem(title: headline(), action: nil, keyEquivalent: ""); s.isEnabled = false; m.addItem(s)
        if let t = status.supportText, !t.isEmpty { let i = NSMenuItem(title: t, action: nil, keyEquivalent: ""); i.isEnabled = false; m.addItem(i) }
        m.addItem(.separator())
        if status.allowSupport == true && fresh {
            m.addItem(NSMenuItem(title: "Request support", action: #selector(support), keyEquivalent: ""))
            let unread = status.chatUnread ?? 0
            m.addItem(NSMenuItem(title: unread > 0 ? "Chat with support (\(unread) new)" : "Chat with support", action: #selector(chat), keyEquivalent: ""))
            m.addItem(.separator())
        }
        m.addItem(NSMenuItem(title: "About Helm Agent", action: #selector(about), keyEquivalent: ""))
        for i in m.items where i.action != nil { i.target = self }
        return m
    }

    @objc func chat() {
        guard let c = status.control, let t = status.chatToken, let u = URL(string: "http://\(c)/chat/\(t)/") else { return }
        NSWorkspace.shared.open(u)
    }

    @objc func support() {
        guard let c = status.control, let u = URL(string: "http://\(c)/support") else { return }
        var r = URLRequest(url: u); r.httpMethod = "POST"; r.timeoutInterval = 8
        r.setValue("1", forHTTPHeaderField: "X-Helm-Tray")
        let body = ["msg": "Support requested from the menu bar on \(status.computer ?? "this Mac") by \(NSUserName())"]
        r.httpBody = try? JSONSerialization.data(withJSONObject: body)
        URLSession.shared.dataTask(with: r) { _, resp, err in
            DispatchQueue.main.async {
                let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
                let text: String
                if err != nil { text = "Could not reach the Helm agent on this Mac." }
                else if code == 204 { text = "Your request was sent. Your administrator will see it in the Helm portal." }
                else if code == 429 { text = "A request was sent a moment ago. Please wait a minute before sending another." }
                else { text = "The request could not be sent because this Mac is not connected to the portal right now." }
                let a = NSAlert(); a.messageText = "Helm Agent"; a.informativeText = text; a.runModal()
            }
        }.resume()
    }

    @objc func about() {
        let a = NSAlert(); a.messageText = "Helm Agent"
        a.informativeText = "Version \(status.version ?? "unknown")\n\(headline())"
        a.runModal()
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory) // menu bar only, no Dock icon
let delegate = App()
app.delegate = delegate
app.run()
