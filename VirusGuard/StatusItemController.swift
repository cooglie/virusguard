import AppKit

/// Status-Icon in der Menüleiste + Timer-Steuerung.
final class StatusItemController {

    private let statusItem: NSStatusItem
    private var scanner: Scanner
    private var config: VirusGuardConfig
    private var timer: Timer?
    private var isScanning = false
    private let progressWindow = ProgressWindow()
    private var configWindow: ConfigWindow?

    /// Callback, das der AppDelegate setzt, um den Fund-Dialog anzuzeigen.
    var onFindingsDetected: ((ScanResult) -> Void)?
    /// Callback für jeden abgeschlossenen Scan (auch sauber) → Report-Fenster.
    var onScanCompleted: ((ScanResult) -> Void)?

    init(config: VirusGuardConfig) {
        self.config = config
        self.scanner = Scanner(config: config)
        self.statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        setupMenu()
        updateIcon(state: .idle)
    }

    // MARK: - Start / Stop

    func start() {
        scheduleNextScan()
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    /// Startet den Scan sofort (manuell oder per Timer).
    func scanNow() {
        guard !isScanning else { return }
        isScanning = true
        updateIcon(state: .scanning)
        progressWindow.show()

        scanner.scan(progress: { [weak self] scanned, total, currentFile in
            self?.progressWindow.update(scanned: scanned, total: total, currentFile: currentFile)
        }, finding: { [weak self] path, signature in
            self?.progressWindow.reportFinding(path: path, signature: signature)
        }, completion: { [weak self] result in
            guard let self = self else { return }
            self.progressWindow.hide()
            self.isScanning = false
            self.handle(result: result)
            if self.config.scanOnce {
                NSApp.terminate(nil)
            } else {
                self.scheduleNextScan()
            }
        })
    }

    // MARK: - Timer

    private func scheduleNextScan() {
        timer?.invalidate()

        let lower = max(1, config.minIntervalSeconds)
        let upper = max(lower, config.maxIntervalSeconds)
        let range = UInt32(upper - lower + 1)
        let random = Int(arc4random_uniform(range)) + lower
        let interval = TimeInterval(random)

        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: false) { [weak self] _ in
            self?.scanNow()
        }
        updateIcon(state: .idle, nextScanIn: interval)
    }

    // MARK: - Ergebnis-Verarbeitung

    private func handle(result: ScanResult) {
        if let err = result.engineError {
            // Engine-Fehler → Nutzer klar informieren, damit nicht der Eindruck
            // entsteht, es werde "gar nichts" gescannt.
            NSLog("[VirusGuard] Engine-Fehler: \(err)")
            updateIcon(state: .alert)
            showEngineErrorDialog(err)
            return
        }

        if result.findings.isEmpty {
            NSLog("[VirusGuard] Scan sauber (exit \(result.exitCode)).")
            updateIcon(state: .idle)
            onScanCompleted?(result)
            return
        }

        // Funde → AppDelegate zeigt Report
        NSLog("[VirusGuard] \(result.findings.count) Fund(e) erkannt.")
        updateIcon(state: .alert)
        onFindingsDetected?(result)
        onScanCompleted?(result)
    }

    // MARK: - Engine-Fehler-Dialog

    /// Zeigt einen modalen Dialog bei Engine-Fehlern (z. B. clamscan fehlt).
    private func showEngineErrorDialog(_ message: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "VirusGuard konnte nicht scannen"
        alert.informativeText = message
        alert.addButton(withTitle: "Einstellungen öffnen")
        alert.addButton(withTitle: "Schließen")
        NSApp.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            openConfig()
        }
    }

    // MARK: - Icon

    private enum IconState {
        case idle, scanning, alert
    }

    private func updateIcon(state: IconState, nextScanIn: TimeInterval? = nil) {
        let title: String
        switch state {
        case .idle:
            title = "🛡️"
        case .scanning:
            title = "🔍"
        case .alert:
            title = "⚠️"
        }
        statusItem.button?.title = title

        // Tooltip
        if state == .scanning {
            statusItem.button?.toolTip = "VirusGuard scannt gerade …"
        } else if let secs = nextScanIn {
            let mins = Int(secs) / 60
            statusItem.button?.toolTip = "VirusGuard – nächster Scan in ca. \(mins) Min."
        } else {
            statusItem.button?.toolTip = "VirusGuard – aktiv"
        }
    }

    // MARK: - Menü

    private func setupMenu() {
        let menu = NSMenu()
        menu.autoenablesItems = true

        let scanItem = NSMenuItem(title: "Jetzt scannen", action: #selector(scanNowMenu), keyEquivalent: "s")
        let configItem = NSMenuItem(title: "Einstellungen …", action: #selector(openConfig), keyEquivalent: ",")
        let quitItem = NSMenuItem(title: "VirusGuard beenden", action: #selector(quit), keyEquivalent: "q")

        // WICHTIG: ohne target sind die Items bei einer reinen Menüleisten-App
        // (kein Fenster/responder chain) ausgegraut.
        [scanItem, configItem, quitItem].forEach { $0.target = self }

        menu.addItem(scanItem)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(configItem)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(quitItem)
        statusItem.menu = menu
    }

    @objc private func scanNowMenu() { scanNow() }

    @objc private func openConfig() {
        // Aktuelle Config neu laden (falls extern geändert) und Fenster öffnen.
        config = VirusGuardConfig.load()
        let w = ConfigWindow(config: config) { [weak self] newConfig in
            guard let self = self else { return }
            self.config = newConfig
            self.scanner = Scanner(config: newConfig)
            // Timer neu planen mit neuen Intervallen
            self.scheduleNextScan()
            NSLog("[VirusGuard] Konfiguration aktualisiert.")
        }
        configWindow = w
        w.show()
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }
}
