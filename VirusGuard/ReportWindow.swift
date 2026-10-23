import AppKit

/// Ergebnis-Fenster nach einem Scan: Zusammenfassung (Dauer, Dateien, Status),
/// Liste der Funde mit Aktionen (Quarantäne / Löschen / Ignorieren) und eine
/// "sauber"-Ansicht, wenn nichts gefunden wurde.
final class ReportWindow {

    private let panel: NSPanel

    /// Callback für jede Fund-Aktion. Wird auf dem Main-Thread aufgerufen.
    /// Liefert (Pfad, Signatur) – der QuarantineManager braucht beides.
    var onQuarantine: ((String, String) -> Bool)?
    var onDelete: ((String) -> Bool)?
    /// Meldung bei Quarantäne-Fehlern (TOCTOU, Symlink etc.) zur Anzeige.
    var onQuarantineMessage: ((String) -> Void)?

    /// Aktuelle Funde (Pfad + Signatur), ggf. mit Status aktualisiert.
    struct FindingRow {
        let path: String
        let signature: String
        var status: String   // "offen", "quarantäne", "gelöscht", "ignoriert"
    }
    private var rows: [FindingRow] = []
    private var tableView: NSTableView!
    /// Delegate festhalten (TableView.delegate ist weak → sonst deallokiert).
    private var findingDelegate: FindingDelegate?
    private var findingDataSource: FindingDataSource?

    init() {
        panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 640, height: 440),
                        styleMask: [.titled, .closable, .resizable, .miniaturizable],
                        backing: .buffered, defer: false)
        panel.title = "VirusGuard – Scan-Report"
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.isRestorable = false
        panel.center()
    }

    // MARK: - Anzeige

    /// Zeigt den Report für das übergebene Scan-Ergebnis.
    func present(result: ScanResult) {
        rows = result.findings.map {
            FindingRow(path: $0.path, signature: $0.signature, status: "offen")
        }
        buildContent(result: result)
        panel.center()
        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func buildContent(result: ScanResult) {
        // Ggf. alte View-Hierarchie entfernen (mehrfaches present()).
        panel.contentView?.subviews.forEach { $0.removeFromSuperview() }

        let container = NSView()
        container.translatesAutoresizingMaskIntoConstraints = false

        // Kopf: Status-Icon + Überschrift
        let iconChar: String
        switch result.status {
        case .clean: iconChar = "✅"
        case .infected: iconChar = "⚠️"
        case .scanError: iconChar = "⚠️"
        case .engineError: iconChar = "🚫"
        }
        let icon = NSTextField(labelWithString: iconChar)
        icon.font = .systemFont(ofSize: 40)
        icon.translatesAutoresizingMaskIntoConstraints = false

        let titleText: String
        let subtitleText: String
        switch result.status {
        case .infected:
            titleText = "\(result.findings.count) Bedrohung\(result.findings.count == 1 ? "" : "en") erkannt"
            subtitleText = "Bitte überprüfe die Funde und wähle eine Aktion."
        case .engineError(let msg):
            titleText = "Scan konnte nicht gestartet werden"
            subtitleText = msg
        case .scanError(let msg):
            titleText = "Scan nicht erfolgreich abgeschlossen"
            subtitleText = msg
        case .clean:
            titleText = "Keine Bedrohungen gefunden"
            subtitleText = "Dein System ist sauber."
        }
        let titleLabel = NSTextField(labelWithString: titleText)
        titleLabel.font = .systemFont(ofSize: 18, weight: .semibold)
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        let subtitleLabel = NSTextField(labelWithString: subtitleText)
        subtitleLabel.font = .systemFont(ofSize: 12)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.translatesAutoresizingMaskIntoConstraints = false

        // Statistik-Zeile
        let stats = NSTextField(labelWithString: statsString(result: result))
        stats.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
        stats.textColor = .secondaryLabelColor
        stats.translatesAutoresizingMaskIntoConstraints = false

        container.addSubview(icon)
        container.addSubview(titleLabel)
        container.addSubview(subtitleLabel)
        container.addSubview(stats)

        // Funde-Tabelle (nur wenn Funde vorhanden)
        if !rows.isEmpty {
            tableView = NSTableView()
            tableView.headerView = nil
            tableView.rowHeight = 28
            tableView.intercellSpacing = NSSize(width: 8, height: 0)
            tableView.backgroundColor = NSColor.windowBackgroundColor
            tableView.gridColor = NSColor.separatorColor
            tableView.gridStyleMask = .solidHorizontalGridLineMask

            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("col"))
            col.width = 600
            tableView.addTableColumn(col)

            let ds = FindingDataSource()
            ds.rows = rows
            findingDataSource = ds
            tableView.dataSource = ds
            let dlg = FindingDelegate(onQuarantine: { [weak self] idx in
                self?.actOnRow(idx, action: .quarantine)
            }, onDelete: { [weak self] idx in
                self?.actOnRow(idx, action: .delete)
            }, onIgnore: { [weak self] idx in
                self?.actOnRow(idx, action: .ignore)
            })
            findingDelegate = dlg
            tableView.delegate = dlg
            dlg.window = self

            let scroll = NSScrollView()
            scroll.translatesAutoresizingMaskIntoConstraints = false
            scroll.hasVerticalScroller = true
            scroll.autohidesScrollers = true
            scroll.drawsBackground = false
            scroll.documentView = tableView
            scroll.borderType = .bezelBorder
            container.addSubview(scroll)

            // Buttons-Leiste unten
            let quarantineAll = NSButton(title: "Alle in Quarantäne", target: self, action: #selector(quarantineAll))
            quarantineAll.translatesAutoresizingMaskIntoConstraints = false
            let deleteAll = NSButton(title: "Alle löschen", target: self, action: #selector(deleteAll))
            deleteAll.translatesAutoresizingMaskIntoConstraints = false
            deleteAll.bezelColor = NSColor.systemRed
            container.addSubview(quarantineAll)
            container.addSubview(deleteAll)

            NSLayoutConstraint.activate([
                scroll.topAnchor.constraint(equalTo: stats.bottomAnchor, constant: 12),
                scroll.leadingAnchor.constraint(equalTo: container.leadingAnchor),
                scroll.trailingAnchor.constraint(equalTo: container.trailingAnchor),

                quarantineAll.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 10),
                quarantineAll.bottomAnchor.constraint(equalTo: container.bottomAnchor),
                quarantineAll.leadingAnchor.constraint(equalTo: container.leadingAnchor),

                deleteAll.centerYAnchor.constraint(equalTo: quarantineAll.centerYAnchor),
                deleteAll.leadingAnchor.constraint(equalTo: quarantineAll.trailingAnchor, constant: 12),
            ])
        }

        // Schließen-Button
        let close = NSButton(title: "Schließen", target: self, action: #selector(close))
        close.keyEquivalent = "\r"
        close.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(close)

        // Container in die bestehende contentView einhängen (NICHT contentView
        // ersetzen – sonst werden die soeben aktivierten Constraints ungültig
        // und AppKit wirft beim Aktivieren eine Exception → Crash).
        let cv = panel.contentView!
        cv.addSubview(container)

        NSLayoutConstraint.activate([
            container.topAnchor.constraint(equalTo: cv.topAnchor, constant: 20),
            container.bottomAnchor.constraint(equalTo: cv.bottomAnchor, constant: -20),
            container.leadingAnchor.constraint(equalTo: cv.leadingAnchor, constant: 24),
            container.trailingAnchor.constraint(equalTo: cv.trailingAnchor, constant: -24),

            icon.topAnchor.constraint(equalTo: container.topAnchor),
            icon.leadingAnchor.constraint(equalTo: container.leadingAnchor),

            titleLabel.topAnchor.constraint(equalTo: container.topAnchor, constant: 4),
            titleLabel.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 14),

            subtitleLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 2),
            subtitleLabel.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),

            stats.topAnchor.constraint(equalTo: subtitleLabel.bottomAnchor, constant: 10),
            stats.leadingAnchor.constraint(equalTo: container.leadingAnchor),

            close.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            close.trailingAnchor.constraint(equalTo: container.trailingAnchor),
        ])
    }

    private func statsString(result: ScanResult) -> String {
        let mins = Int(result.durationSeconds) / 60
        let secs = Int(result.durationSeconds) % 60
        let dur = mins > 0 ? "\(mins) Min \(secs) Sek" : "\(secs) Sek"
        let timeStr = DateFormatter.localizedString(from: Date(),
                                                    dateStyle: .short,
                                                    timeStyle: .short)
        return "Geprüft: \(result.filesScanned) Dateien   ·   Dauer: \(dur)   ·   \(timeStr)"
    }

    // MARK: - Aktionen

    private enum Action { case quarantine, delete, ignore }

    private func actOnRow(_ index: Int, action: Action) {
        guard index >= 0, index < rows.count else { return }
        let path = rows[index].path
        let sig = rows[index].signature

        switch action {
        case .quarantine:
            let ok = onQuarantine?(path, sig) ?? false
            rows[index].status = ok ? "✅ In Quarantäne" : "❌ Fehler"
            if !ok { onQuarantineMessage?("Datei konnte nicht quarantäniert werden (evtl. verändert oder Symlink).") }
        case .delete:
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "Datei endgültig löschen?"
            alert.informativeText = "\"\((path as NSString).lastPathComponent)\" wird unwiderruflich gelöscht."
            alert.addButton(withTitle: "Löschen")
            alert.addButton(withTitle: "Abbrechen")
            if alert.runModal() == .alertFirstButtonReturn {
                let ok = onDelete?(path) ?? false
                rows[index].status = ok ? "🗑 Gelöscht" : "❌ Fehler"
            } else {
                return
            }
        case .ignore:
            rows[index].status = "Ignoriert"
        }
        tableView?.reloadData(forRowIndexes: IndexSet(integer: index),
                              columnIndexes: IndexSet(integer: 0))
    }

    @objc private func quarantineAll() {
        var failures: [String] = []
        for i in 0..<rows.count where rows[i].status == "offen" {
            let path = rows[i].path
            let sig = rows[i].signature
            let ok = onQuarantine?(path, sig) ?? false
            rows[i].status = ok ? "✅ In Quarantäne" : "❌ Fehler"
            if !ok { failures.append((path as NSString).lastPathComponent) }
        }
        if !failures.isEmpty {
            onQuarantineMessage?("\(failures.count) Datei(en) konnten nicht quarantäniert werden: \(failures.joined(separator: ", "))")
        }
        tableView?.reloadData()
    }

    @objc private func deleteAll() {
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "\(rows.filter { $0.status == "offen" }.count) Dateien löschen?"
        alert.informativeText = "Alle offenen Funde werden unwiderruflich gelöscht."
        alert.addButton(withTitle: "Alle löschen")
        alert.addButton(withTitle: "Abbrechen")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        for i in 0..<rows.count where rows[i].status == "offen" {
            let ok = onDelete?(rows[i].path) ?? false
            rows[i].status = ok ? "🗑 Gelöscht" : "❌ Fehler"
        }
        tableView?.reloadData()
    }

    @objc private func close() {
        panel.orderOut(nil)
    }
}

// MARK: - Table data source & delegate (In-Cell-Buttons)

private final class FindingDataSource: NSObject, NSTableViewDataSource {
    var rows: [ReportWindow.FindingRow] = []

    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }
}

private final class FindingDelegate: NSObject, NSTableViewDelegate {
    private let onQuarantine: (Int) -> Void
    private let onDelete: (Int) -> Void
    private let onIgnore: (Int) -> Void
    weak var window: ReportWindow?

    init(onQuarantine: @escaping (Int) -> Void,
         onDelete: @escaping (Int) -> Void,
         onIgnore: @escaping (Int) -> Void) {
        self.onQuarantine = onQuarantine
        self.onDelete = onDelete
        self.onIgnore = onIgnore
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let ds = tableView.dataSource as? FindingDataSource, row < ds.rows.count else { return nil }
        let f = ds.rows[row]

        let cell = NSTableCellView()
        cell.translatesAutoresizingMaskIntoConstraints = false

        let name = NSTextField(labelWithString: (f.path as NSString).lastPathComponent)
        name.font = .systemFont(ofSize: 12, weight: .medium)
        name.lineBreakMode = .byTruncatingMiddle
        name.translatesAutoresizingMaskIntoConstraints = false

        let sig = NSTextField(labelWithString: f.signature)
        sig.font = .monospacedDigitSystemFont(ofSize: 10, weight: .regular)
        sig.textColor = .systemRed
        sig.translatesAutoresizingMaskIntoConstraints = false

        let status = NSTextField(labelWithString: f.status)
        status.font = .systemFont(ofSize: 11)
        status.alignment = .right
        status.translatesAutoresizingMaskIntoConstraints = false

        // Buttons nur, wenn noch offen
        let btnQuar = NSButton(title: "Quarantäne", target: self, action: #selector(quarantine(_:)))
        btnQuar.tag = row
        btnQuar.bezelStyle = .roundRect
        btnQuar.controlSize = .small
        btnQuar.translatesAutoresizingMaskIntoConstraints = false

        let btnDel = NSButton(title: "Löschen", target: self, action: #selector(deleteTapped(_:)))
        btnDel.tag = row
        btnDel.bezelStyle = .roundRect
        btnDel.controlSize = .small
        btnDel.translatesAutoresizingMaskIntoConstraints = false

        let btnIgn = NSButton(title: "Ignorieren", target: self, action: #selector(ignore(_:)))
        btnIgn.tag = row
        btnIgn.bezelStyle = .roundRect
        btnIgn.controlSize = .small
        btnIgn.translatesAutoresizingMaskIntoConstraints = false

        cell.addSubview(name)
        cell.addSubview(sig)
        cell.addSubview(status)
        cell.addSubview(btnQuar)
        cell.addSubview(btnDel)
        cell.addSubview(btnIgn)

        let buttonsVisible = (f.status == "offen")
        btnQuar.isHidden = !buttonsVisible
        btnDel.isHidden = !buttonsVisible
        btnIgn.isHidden = !buttonsVisible
        status.isHidden = buttonsVisible

        NSLayoutConstraint.activate([
            name.topAnchor.constraint(equalTo: cell.topAnchor, constant: 4),
            name.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 4),
            name.trailingAnchor.constraint(lessThanOrEqualTo: status.leadingAnchor, constant: -8),

            sig.topAnchor.constraint(equalTo: name.bottomAnchor, constant: 1),
            sig.leadingAnchor.constraint(equalTo: name.leadingAnchor),
            sig.bottomAnchor.constraint(equalTo: cell.bottomAnchor, constant: -4),

            status.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
            status.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),

            btnIgn.trailingAnchor.constraint(equalTo: status.leadingAnchor, constant: -8),
            btnIgn.centerYAnchor.constraint(equalTo: cell.centerYAnchor),

            btnDel.trailingAnchor.constraint(equalTo: btnIgn.leadingAnchor, constant: -8),
            btnDel.centerYAnchor.constraint(equalTo: cell.centerYAnchor),

            btnQuar.trailingAnchor.constraint(equalTo: btnDel.leadingAnchor, constant: -8),
            btnQuar.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
        ])
        return cell
    }

    @objc private func quarantine(_ sender: NSButton) { onQuarantine(sender.tag) }
    @objc private func deleteTapped(_ sender: NSButton) { onDelete(sender.tag) }
    @objc private func ignore(_ sender: NSButton) { onIgnore(sender.tag) }
}

// MARK: - Quarantine / Delete helper (auf Scanner delegiert)

extension ReportWindow {
    /// Convenience: verdrahtet Quarantäne/Löschen über Scanner + QuarantineManager.
    /// Der Manager prüft Datei-Identität, verhindert Überschreiben und protokolliert.
    func wireActions(scanner: Scanner, quarantineManager: QuarantineManager) {
        onQuarantine = { path, signature in
            scanner.quarantine(file: path, signature: signature)
        }
        onQuarantineMessage = { msg in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Quarantäne nicht möglich"
            alert.informativeText = msg
            alert.addButton(withTitle: "OK")
            NSApp.activate(ignoringOtherApps: true)
            _ = alert.runModal()
        }
        // Löschen läuft ebenfalls über den Manager (protokolliert + sicher).
        onDelete = { path in
            let result = quarantineManager.delete(quarantinedPath: path)
            if !result.success {
                // Falls noch nicht in Quarantäne: direkt löschen versuchen.
                do {
                    try FileManager.default.removeItem(atPath: path)
                    return true
                } catch {
                    NSLog("[VirusGuard] Löschen fehlgeschlagen: \(error.localizedDescription)")
                    return false
                }
            }
            return result.success
        }
    }
}
