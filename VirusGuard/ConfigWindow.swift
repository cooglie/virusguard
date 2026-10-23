import AppKit

/// Grafisches Konfigurationsfenster für VirusGuard.
/// Zeigt alle Einstellungen als Formular; beim Speichern wird die Config neu geschrieben
/// und der Scanner/Timer des StatusItemController übernommen.
final class ConfigWindow: NSObject, NSTextFieldDelegate, NSControlTextEditingDelegate {

    private var config: VirusGuardConfig
    private let onComplete: (VirusGuardConfig) -> Void

    private let panel: NSPanel

    // Formular-Elemente
    private var minIntervalField: NSTextField!
    private var maxIntervalField: NSTextField!
    private var pathsTextView: NSTextView!
    private var clamScanField: NSTextField!
    private var clamDbField: NSTextField!
    private var quarantineField: NSTextField!
    private var xProtectCheckbox: NSButton!
    private var scanOnceCheckbox: NSButton!

    init(config: VirusGuardConfig, onComplete: @escaping (VirusGuardConfig) -> Void) {
        self.config = config
        self.onComplete = onComplete

        panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 700, height: 800),
                        styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                        backing: .buffered, defer: false)
        super.init()
        panel.title = "VirusGuard – Konfiguration"
        panel.isFloatingPanel = true
        panel.center()
        buildUI()
        populate()
    }

    func show() {
        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: - UI

    private func buildUI() {
        let content = NSView()
        content.translatesAutoresizingMaskIntoConstraints = false
        panel.contentView = content

        let labelWidth: CGFloat = 190
        let rowH: CGFloat = 34
        let fieldFont: NSFont = .systemFont(ofSize: 14)
        var constraints: [NSLayoutConstraint] = []

        // Hilfsfunktion: Label + Feld in einer Reihe
        func row(label: String, _ field: NSView, height: CGFloat = rowH) -> NSView {
            let l = NSTextField(labelWithString: label)
            l.alignment = .right
            l.font = .systemFont(ofSize: 14, weight: .medium)
            l.translatesAutoresizingMaskIntoConstraints = false
            field.translatesAutoresizingMaskIntoConstraints = false
            let r = NSView()
            r.translatesAutoresizingMaskIntoConstraints = false
            r.addSubview(l)
            r.addSubview(field)
            constraints += [
                l.leadingAnchor.constraint(equalTo: r.leadingAnchor),
                l.widthAnchor.constraint(equalToConstant: labelWidth),
                l.centerYAnchor.constraint(equalTo: r.centerYAnchor),
                field.leadingAnchor.constraint(equalTo: l.trailingAnchor, constant: 12),
                field.trailingAnchor.constraint(equalTo: r.trailingAnchor),
                field.centerYAnchor.constraint(equalTo: r.centerYAnchor),
                field.heightAnchor.constraint(equalToConstant: height),
                r.heightAnchor.constraint(equalToConstant: max(height, rowH))
            ]
            return r
        }

        // Vertikaler StackView als Container
        let stackView = NSStackView()
        stackView.translatesAutoresizingMaskIntoConstraints = false
        stackView.orientation = .vertical
        stackView.alignment = .leading
        stackView.spacing = 16
        content.addSubview(stackView)
        constraints += [
            stackView.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            stackView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 24),
            stackView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -24),
            stackView.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -24)
        ]

        // 1. Min. Intervall
        let minField = NSTextField()
        minField.placeholderString = "z. B. 600 (10 Min)"
        minField.font = fieldFont
        minField.tag = 1
        minField.delegate = self
        minIntervalField = minField
        stackView.addArrangedSubview(row(label: "Min. Intervall (Sek):", minField))

        // 2. Max. Intervall
        let maxField = NSTextField()
        maxField.placeholderString = "z. B. 7200 (2 Std)"
        maxField.font = fieldFont
        maxField.tag = 2
        maxField.delegate = self
        maxIntervalField = maxField
        stackView.addArrangedSubview(row(label: "Max. Intervall (Sek):", maxField))

        // 3. Scan-Pfade: Label + ScrollView in einer Row
        let pathsLabel = NSTextField(labelWithString: "Scan-Pfade")
        pathsLabel.font = .systemFont(ofSize: 14, weight: .medium)
        pathsLabel.alignment = .right
        pathsLabel.translatesAutoresizingMaskIntoConstraints = false
        let scrollView = NSScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .bezelBorder
        pathsTextView = NSTextView()
        pathsTextView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        pathsTextView.isEditable = true
        pathsTextView.isSelectable = true
        pathsTextView.autoresizingMask = [.width]
        scrollView.documentView = pathsTextView
        let pathsRow = NSView()
        pathsRow.translatesAutoresizingMaskIntoConstraints = false
        pathsRow.addSubview(pathsLabel)
        pathsRow.addSubview(scrollView)
        constraints += [
            pathsLabel.leadingAnchor.constraint(equalTo: pathsRow.leadingAnchor),
            pathsLabel.widthAnchor.constraint(equalToConstant: labelWidth),
            pathsLabel.topAnchor.constraint(equalTo: pathsRow.topAnchor, constant: 6),
            scrollView.leadingAnchor.constraint(equalTo: pathsLabel.trailingAnchor, constant: 12),
            scrollView.trailingAnchor.constraint(equalTo: pathsRow.trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: pathsRow.topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: pathsRow.bottomAnchor),
            scrollView.heightAnchor.constraint(equalToConstant: 160),
            pathsRow.heightAnchor.constraint(equalToConstant: 160)
        ]
        stackView.addArrangedSubview(pathsRow)

        // 4. clamscan Pfad + Browse
        let clamField = NSTextField()
        clamField.placeholderString = "/usr/local/bin/clamscan"
        clamField.font = fieldFont
        clamScanField = clamField
        let clamBrowse = NSButton(title: "…", target: self, action: #selector(browseClamScan))
        clamBrowse.bezelStyle = .rounded
        clamBrowse.font = .systemFont(ofSize: 14)
        let clamRowView = NSView()
        clamRowView.translatesAutoresizingMaskIntoConstraints = false
        clamRowView.addSubview(clamField)
        clamRowView.addSubview(clamBrowse)
        constraints += [
            clamField.leadingAnchor.constraint(equalTo: clamRowView.leadingAnchor),
            clamField.topAnchor.constraint(equalTo: clamRowView.topAnchor),
            clamField.bottomAnchor.constraint(equalTo: clamRowView.bottomAnchor),
            clamBrowse.leadingAnchor.constraint(equalTo: clamField.trailingAnchor, constant: 10),
            clamBrowse.trailingAnchor.constraint(equalTo: clamRowView.trailingAnchor),
            clamBrowse.widthAnchor.constraint(equalToConstant: 44),
            clamBrowse.centerYAnchor.constraint(equalTo: clamRowView.centerYAnchor)
        ]
        stackView.addArrangedSubview(row(label: "clamscan Pfad:", clamRowView))

        // 5. ClamAV Datenbank
        let dbField = NSTextField()
        dbField.placeholderString = "(leer = Standard)"
        dbField.font = fieldFont
        clamDbField = dbField
        stackView.addArrangedSubview(row(label: "ClamAV Datenbank:", dbField))

        // 6. Quarantäne-Ordner + Browse
        let qField = NSTextField()
        qField.placeholderString = "~/Desktop/Quarantine"
        qField.font = fieldFont
        quarantineField = qField
        let qBrowse = NSButton(title: "…", target: self, action: #selector(browseQuarantine))
        qBrowse.bezelStyle = .rounded
        qBrowse.font = .systemFont(ofSize: 14)
        let qRowView = NSView()
        qRowView.translatesAutoresizingMaskIntoConstraints = false
        qRowView.addSubview(qField)
        qRowView.addSubview(qBrowse)
        constraints += [
            qField.leadingAnchor.constraint(equalTo: qRowView.leadingAnchor),
            qField.topAnchor.constraint(equalTo: qRowView.topAnchor),
            qField.bottomAnchor.constraint(equalTo: qRowView.bottomAnchor),
            qBrowse.leadingAnchor.constraint(equalTo: qField.trailingAnchor, constant: 10),
            qBrowse.trailingAnchor.constraint(equalTo: qRowView.trailingAnchor),
            qBrowse.widthAnchor.constraint(equalToConstant: 44),
            qBrowse.centerYAnchor.constraint(equalTo: qRowView.centerYAnchor)
        ]
        stackView.addArrangedSubview(row(label: "Quarantäne-Ordner:", qRowView))

        // 7. Checkboxen
        let xProtect = NSButton(checkboxWithTitle: "XProtect-Updates im Hintergrund anstoßen", target: self, action: #selector(toggleXProtect))
        xProtect.font = .systemFont(ofSize: 14)
        xProtectCheckbox = xProtect
        stackView.addArrangedSubview(xProtect)

        let scanOnce = NSButton(checkboxWithTitle: "Nur einmal scannen, dann beenden (Debug)", target: self, action: #selector(toggleScanOnce))
        scanOnce.font = .systemFont(ofSize: 14)
        scanOnceCheckbox = scanOnce
        stackView.addArrangedSubview(scanOnce)

        // 8. Buttons (rechtsbündig)
        let saveBtn = NSButton(title: "Speichern", target: self, action: #selector(save))
        saveBtn.keyEquivalent = "\r"
        saveBtn.font = .systemFont(ofSize: 14, weight: .medium)
        let cancelBtn = NSButton(title: "Abbrechen", target: self, action: #selector(cancel))
        cancelBtn.keyEquivalent = "\u{1b}"
        cancelBtn.font = .systemFont(ofSize: 14)
        let btnRow = NSView()
        btnRow.translatesAutoresizingMaskIntoConstraints = false
        btnRow.addSubview(cancelBtn)
        btnRow.addSubview(saveBtn)
        constraints += [
            cancelBtn.trailingAnchor.constraint(equalTo: btnRow.centerXAnchor, constant: -10),
            cancelBtn.centerYAnchor.constraint(equalTo: btnRow.centerYAnchor),
            saveBtn.leadingAnchor.constraint(equalTo: btnRow.centerXAnchor, constant: 10),
            saveBtn.centerYAnchor.constraint(equalTo: btnRow.centerYAnchor),
            btnRow.heightAnchor.constraint(equalToConstant: 40)
        ]
        stackView.addArrangedSubview(btnRow)

        NSLayoutConstraint.activate(constraints)

        // Fenstergröße automatisch an den Inhalt anpassen
        content.layoutSubtreeIfNeeded()
        let fitSize = stackView.fittingSize
        let titleBarExtra: CGFloat = 28
        let finalWidth: CGFloat = 760
        let finalHeight = fitSize.height + 48 + titleBarExtra
        panel.setContentSize(NSSize(width: finalWidth, height: finalHeight))
        panel.minSize = NSSize(width: finalWidth, height: finalHeight)
        panel.maxSize = NSSize(width: finalWidth, height: finalHeight + 200)
    }

    private func populate() {
        minIntervalField.stringValue = String(config.minIntervalSeconds)
        maxIntervalField.stringValue = String(config.maxIntervalSeconds)
        pathsTextView.string = config.scanPaths.joined(separator: "\n")
        clamScanField.stringValue = config.clamScanPath
        clamDbField.stringValue = config.clamDatabase
        quarantineField.stringValue = config.quarantineFolder
        xProtectCheckbox.state = config.triggerXProtectUpdate ? .on : .off
        scanOnceCheckbox.state = config.scanOnce ? .on : .off
    }

    // MARK: - Actions

    @objc private func toggleXProtect() {
        config.triggerXProtectUpdate = (xProtectCheckbox.state == .on)
    }

    @objc private func toggleScanOnce() {
        config.scanOnce = (scanOnceCheckbox.state == .on)
    }

    @objc private func browseClamScan() {
        let open = NSOpenPanel()
        open.canChooseFiles = true
        open.canChooseDirectories = false
        open.allowsMultipleSelection = false
        open.directoryURL = URL(fileURLWithPath: "/usr/local/bin")
        if open.runModal() == .OK, let url = open.url {
            clamScanField.stringValue = url.path
        }
    }

    @objc private func browseQuarantine() {
        let open = NSOpenPanel()
        open.canChooseFiles = false
        open.canChooseDirectories = true
        open.allowsMultipleSelection = false
        if open.runModal() == .OK, let url = open.url {
            quarantineField.stringValue = url.path
        }
    }

    @objc private func save() {
        // Werte übernehmen
        config.minIntervalSeconds = Int(minIntervalField.stringValue) ?? config.minIntervalSeconds
        config.maxIntervalSeconds = Int(maxIntervalField.stringValue) ?? config.maxIntervalSeconds
        config.scanPaths = pathsTextView.string
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        config.clamScanPath = clamScanField.stringValue.trimmingCharacters(in: .whitespaces)
        config.clamDatabase = clamDbField.stringValue.trimmingCharacters(in: .whitespaces)
        config.quarantineFolder = quarantineField.stringValue.trimmingCharacters(in: .whitespaces)
        config.triggerXProtectUpdate = (xProtectCheckbox.state == .on)
        config.scanOnce = (scanOnceCheckbox.state == .on)

        // Validierung + Kanonisierung (sichere Defaults, Überschneidungs-Prüfung).
        let warnings = config.validate()
        config.save()
        onComplete(config)
        panel.orderOut(nil)

        // Warnungen anzeigen, damit der Nutzer versteht, was korrigiert wurde.
        if !warnings.isEmpty {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Konfiguration wurde angepasst"
            alert.informativeText = warnings.joined(separator: "\n")
            alert.addButton(withTitle: "OK")
            NSApp.activate(ignoringOtherApps: true)
            _ = alert.runModal()
        }
    }

    @objc private func cancel() {
        panel.orderOut(nil)
    }
}
