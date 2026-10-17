import AppKit

/// Live-Scan-Vorschau-Fenster: Fortschrittsbalken mit %, aktuelle Datei,
/// scrollende Aktivitätsliste der zuletzt gescannten Dateien und live
/// erkannte Funde (rot hervorgehoben).
final class ProgressWindow {

    private let panel: NSPanel
    private let progressBar: NSProgressIndicator
    private let statusLabel: NSTextField
    private let fileLabel: NSTextField
    private let findingsLabel: NSTextField

    /// Scroll-View für die Live-Aktivitätsliste.
    private let scrollView: NSScrollView
    /// Text-View, in die jede gescannte Datei angehängt wird.
    private let logView: NSTextView

    /// Maximal Anzahl Zeilen, die wir im Log behalten (ältere werden entfernt).
    private let maxLogLines = 500
    /// Anzahl bisheriger Funde (live).
    private var findingsCount = 0
    /// Puffer für Log-Zeilen, damit wir ältere kappen können.
    private var logLines: [String] = []

    init() {
        progressBar = NSProgressIndicator()
        progressBar.style = .bar
        progressBar.controlSize = .regular
        progressBar.minValue = 0
        progressBar.maxValue = 100
        progressBar.doubleValue = 0
        progressBar.isIndeterminate = true   // bis wir eine Gesamtzahl kennen
        progressBar.usesThreadedAnimation = true
        progressBar.translatesAutoresizingMaskIntoConstraints = false

        statusLabel = NSTextField(labelWithString: "VirusGuard scannt …")
        statusLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        statusLabel.translatesAutoresizingMaskIntoConstraints = false

        fileLabel = NSTextField(labelWithString: "")
        fileLabel.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
        fileLabel.textColor = .secondaryLabelColor
        fileLabel.lineBreakMode = .byTruncatingMiddle
        fileLabel.translatesAutoresizingMaskIntoConstraints = false

        findingsLabel = NSTextField(labelWithString: "")
        findingsLabel.font = .systemFont(ofSize: 11, weight: .medium)
        findingsLabel.textColor = .systemRed
        findingsLabel.translatesAutoresizingMaskIntoConstraints = false

        // Live-Aktivitätsliste
        logView = NSTextView()
        logView.isEditable = false
        logView.isSelectable = true
        logView.isRichText = true
        logView.font = .monospacedDigitSystemFont(ofSize: 10, weight: .regular)
        logView.textColor = .secondaryLabelColor
        logView.backgroundColor = NSColor.windowBackgroundColor
        logView.textContainerInset = NSSize(width: 4, height: 4)
        logView.autoresizingMask = [.width]

        scrollView = NSScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.drawsBackground = false
        scrollView.documentView = logView

        let container = NSView()
        container.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(statusLabel)
        container.addSubview(progressBar)
        container.addSubview(fileLabel)
        container.addSubview(findingsLabel)
        container.addSubview(scrollView)

        panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 560, height: 380),
                        styleMask: [.titled, .closable, .resizable],
                        backing: .buffered, defer: false)
        panel.contentView = container
        panel.title = "VirusGuard – Live-Scan"
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.isRestorable = false
        panel.center()
        panel.minSize = NSSize(width: 420, height: 260)

        NSLayoutConstraint.activate([
            container.topAnchor.constraint(equalTo: panel.contentView!.topAnchor, constant: 16),
            container.bottomAnchor.constraint(equalTo: panel.contentView!.bottomAnchor, constant: -16),
            container.leadingAnchor.constraint(equalTo: panel.contentView!.leadingAnchor, constant: 20),
            container.trailingAnchor.constraint(equalTo: panel.contentView!.trailingAnchor, constant: -20),

            statusLabel.topAnchor.constraint(equalTo: container.topAnchor),
            statusLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            statusLabel.trailingAnchor.constraint(equalTo: container.trailingAnchor),

            progressBar.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 12),
            progressBar.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            progressBar.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            progressBar.heightAnchor.constraint(equalToConstant: 22),

            fileLabel.topAnchor.constraint(equalTo: progressBar.bottomAnchor, constant: 8),
            fileLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            fileLabel.trailingAnchor.constraint(equalTo: container.trailingAnchor),

            findingsLabel.topAnchor.constraint(equalTo: fileLabel.bottomAnchor, constant: 4),
            findingsLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            findingsLabel.trailingAnchor.constraint(equalTo: container.trailingAnchor),

            scrollView.topAnchor.constraint(equalTo: findingsLabel.bottomAnchor, constant: 10),
            scrollView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: container.bottomAnchor)
        ])
    }

    // MARK: - Anzeige

    /// Zeigt das Fenster zentriert auf dem Bildschirm.
    func show() {
        DispatchQueue.main.async { [self] in
            progressBar.isIndeterminate = true
            progressBar.doubleValue = 0
            progressBar.startAnimation(nil)
            statusLabel.stringValue = "VirusGuard scannt …"
            fileLabel.stringValue = "Vorbereitung …"
            findingsLabel.stringValue = ""
            findingsCount = 0
            logLines.removeAll()
            logView.string = ""
            panel.center()
            panel.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    /// Schaltet auf bestimmten Modus um (mit bekannter Gesamtzahl) oder bleibt unbestimmt.
    func setTotalFileCount(_ total: Int?) {
        DispatchQueue.main.async { [self] in
            if let total = total, total > 0 {
                progressBar.isIndeterminate = false
                progressBar.stopAnimation(nil)
                progressBar.maxValue = Double(total)
                progressBar.doubleValue = 0
            } else {
                progressBar.isIndeterminate = true
                progressBar.startAnimation(nil)
            }
        }
    }

    /// Aktualisiert den Fortschritt. Wird pro gescannter Datei aufgerufen.
    func update(scanned: Int, total: Int?, currentFile: String?) {
        DispatchQueue.main.async { [self] in
            if let total = total, total > 0 {
                if progressBar.isIndeterminate {
                    progressBar.isIndeterminate = false
                    progressBar.stopAnimation(nil)
                }
                progressBar.maxValue = Double(total)
                progressBar.doubleValue = min(Double(scanned), Double(total))
                let pct = total > 0 ? Int(Double(scanned) / Double(total) * 100) : 0
                statusLabel.stringValue = "Scan läuft … \(pct)%"
                fileLabel.stringValue = "\(scanned) / \(total) Dateien"
            } else {
                if !progressBar.isIndeterminate {
                    progressBar.isIndeterminate = true
                    progressBar.startAnimation(nil)
                }
                statusLabel.stringValue = "Scan läuft …"
                fileLabel.stringValue = "\(scanned) Dateien geprüft"
            }

            if let f = currentFile, !f.isEmpty {
                let short = (f as NSString).lastPathComponent
                fileLabel.stringValue = (fileLabel.stringValue) + "  —  " + short
                appendLog(short, found: false)
            }
        }
    }

    /// Wird aufgerufen, wenn clamscan einen Fund meldet (live, noch während des Scans).
    func reportFinding(path: String, signature: String) {
        DispatchQueue.main.async { [self] in
            findingsCount += 1
            findingsLabel.stringValue = "⚠️ \(findingsCount) Fund\(findingsCount == 1 ? "" : "e") — letzte Signatur: \(signature)"
            let short = (path as NSString).lastPathComponent
            appendLog("⚠️ \(short) → \(signature)", found: true)
        }
    }

    func hide() {
        DispatchQueue.main.async { [self] in
            progressBar.stopAnimation(nil)
            panel.orderOut(nil)
        }
    }

    // MARK: - Log

    /// Hängt eine Zeile an die Aktivitätsliste an und kappt alte Zeilen.
    private func appendLog(_ text: String, found: Bool) {
        logLines.append(text)
        if logLines.count > maxLogLines {
            logLines.removeFirst(logLines.count - maxLogLines)
        }

        let attr = NSMutableAttributedString()
        for line in logLines {
            let isFinding = line.hasPrefix("⚠️")
            let attrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.monospacedDigitSystemFont(ofSize: 10, weight: .regular),
                .foregroundColor: isFinding ? NSColor.systemRed : NSColor.secondaryLabelColor
            ]
            attr.append(NSAttributedString(string: line + "\n", attributes: attrs))
        }
        logView.textStorage?.setAttributedString(attr)

        // Ans Ende scrollen, damit die neueste Zeile sichtbar ist.
        let bottom = NSRect(x: 0, y: logView.bounds.height - 1, width: 1, height: 1)
        _ = logView.scrollToVisible(bottom)
    }
}

private extension NSWindow {
    func center() {
        if let screen = NSScreen.main {
            let r = screen.visibleFrame
            setFrameOrigin(NSPoint(x: r.midX - frame.width / 2,
                                   y: r.midY - frame.height / 2))
        }
    }
}
