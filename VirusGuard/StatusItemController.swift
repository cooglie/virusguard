import AppKit

/// Status-Icon in der Menüleiste + Timer-Steuerung.
final class StatusItemController: NSObject, NSMenuDelegate {

    private let statusItem: NSStatusItem
    private var scanner: Scanner
    private var config: VirusGuardConfig
    private var signatureManager: SignatureUpdateManager
    private var timer: Timer?
    private var watchdog: Timer?
    /// Zeitpunkt, an dem der aktuelle Scan begann – für Watchdog-Erkennung.
    private var scanStartedAt: Date?
    /// Obergrenze für einen einzelnen Scan (10 Min). Danach gilt er als hängend.
    private let scanTimeout: TimeInterval = 600
    private var isScanning = false
    private let progressWindow = ProgressWindow()
    private var configWindow: ConfigWindow?
    /// Zeitpunkt des letzten *vollständig erfolgreichen* Scans (.clean oder .infected).
    /// nil, wenn noch kein erfolgreicher Scan stattfand oder der letzte fehlerhaft war.
    private var lastSuccessfulScan: Date?
    /// Zeitpunkt des letzten freshclam-Signaturupdates (nil = unbekannt/nie).
    private var lastSignatureUpdate: Date?
    /// Dauer nachdem Signaturen als „veraltet" gelten (7 Tage).
    private let signatureStaleInterval: TimeInterval = 7 * 24 * 3600

    /// Callback, das der AppDelegate setzt, um den Fund-Dialog anzuzeigen.
    var onFindingsDetected: ((ScanResult) -> Void)?
    /// Callback für jeden abgeschlossenen Scan (auch sauber) → Report-Fenster.
    var onScanCompleted: ((ScanResult) -> Void)?

    init(config: VirusGuardConfig) {
        self.config = config
        self.scanner = Scanner(config: config)
        self.signatureManager = SignatureUpdateManager(config: config)
        self.statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()
        // Initialen Signatur-Stand ermitteln (ohne Netzwerk-Aufruf).
        self.lastSignatureUpdate = signatureManager.lastSignatureUpdate()
        setupMenu()
        updateIcon(state: .idle)
    }

    // MARK: - NSMenuDelegate

    /// Wird aufgerufen, kurz bevor das Menü angezeigt wird – Statuszeilen aktualisieren.
    func menuNeedsUpdate(_ menu: NSMenu) {
        // Die ersten drei Items sind die Statuszeilen (Index 0,1,2).
        if menu.items.count >= 3 {
            menu.items[0].title = statusMenuLine_lastScan()
            menu.items[1].title = statusMenuLine_coverage()
            menu.items[2].title = statusMenuLine_signatures()
        }
    }

    // MARK: - Start / Stop

    func start() {
        scheduleNextScan()
        startWatchdog()
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        watchdog?.invalidate()
        watchdog = nil
    }

    /// Watchdog: prüft periodisch, ob ein Scan hängt (länger als scanTimeout
    /// ohne completion). Wenn ja, wird der Zustand zurückgesetzt und der nächste
    /// Scan neu geplant. Verhindert, dass die App nach einem abgerissenen
    /// clamscan-Prozess stillsteht.
    private func startWatchdog() {
        watchdog?.invalidate()
        watchdog = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            guard self.isScanning, let started = self.scanStartedAt else { return }
            if Date().timeIntervalSince(started) > self.scanTimeout {
                NSLog("[VirusGuard] Watchdog: Scan hängt seit \(Int(self.scanTimeout))s – wird abgebrochen und neu geplant.")
                self.progressWindow.hide()
                self.isScanning = false
                self.scanStartedAt = nil
                self.scheduleNextScan()
            }
        }
    }

    /// Startet den Scan sofort (manuell oder per Timer).
    /// Durch `isScanning` re-entrant-sicher: ein nochmaliger Aufruf (z. B. durch
    /// einen verzögerten Timer-Klick) wird ignoriert.
    func scanNow() {
        guard !isScanning else {
            NSLog("[VirusGuard] scanNow ignoriert – läuft bereits.")
            return
        }
        // Nicht scannen, während ein Signatur-Update läuft – die DB könnte halb
        // geschrieben sein, was zu falschen Ergebnissen führt.
        if signatureManager.isUpdating {
            let a = NSAlert()
            a.alertStyle = .warning
            a.messageText = "Signatur-Update läuft"
            a.informativeText = "Bitte warten, bis die Aktualisierung abgeschlossen ist, bevor Sie scannen."
            a.addButton(withTitle: "OK")
            NSApp.activate(ignoringOtherApps: true)
            _ = a.runModal()
            // Timer neu planen, damit der Scan später nachholt wird.
            scheduleNextScan()
            return
        }
        isScanning = true
        scanStartedAt = Date()
        updateIcon(state: .scanning)
        progressWindow.show()

        let cleanup: () -> Void = { [weak self] in
            guard let self = self else { return }
            self.progressWindow.hide()
            self.isScanning = false
            self.scanStartedAt = nil
        }

        scanner.scan(progress: { [weak self] scanned, total, currentFile in
            self?.progressWindow.update(scanned: scanned, total: total, currentFile: currentFile)
        }, finding: { [weak self] path, signature in
            self?.progressWindow.reportFinding(path: path, signature: signature)
        }, completion: { [weak self] result in
            guard let self = self else { return }
            cleanup()
            self.handle(result: result)
            // Nur bei Engine-Freiheit (kein engineError) als „erfolgreich" zählen.
            if result.engineError == nil {
                self.lastSuccessfulScan = Date()
            }
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
            // Der Scan läuft in einem eigenen Thread (Scanner.scan) – der
            // completion-Callback resettet isScanning auf jeden Fall. Sollte
            // der Scanner-Thread jedoch abreißen (z. B. clamscan-Kill), greift
            // zusätzlich der Watchdog-Timer (startHeartbeat), der einen
            // hängenden Zustand erkennt und den nächsten Scan neu plant.
            self?.scanNow()
        }
        updateIcon(state: .idle, nextScanIn: interval)
    }

    // MARK: - Ergebnis-Verarbeitung

    private func handle(result: ScanResult) {
        // Einheitliche Auswertung über result.status – stellt sicher, dass ein
        // fehlerhafter Scan NIEMALS denselben Status erhält wie ein sauberer Scan.
        switch result.status {
        case .engineError(let msg):
            NSLog("[VirusGuard] Engine-Fehler: \(msg)")
            updateIcon(state: .alert)
            showEngineErrorDialog(msg)

        case .scanError(let msg):
            // Scanfehler (Exit >= 2, Abbruch, korrupte DB) → Warn-Status,
            // niemals „sauber". Nutzer klar informieren.
            NSLog("[VirusGuard] Scan-Fehler: \(msg)")
            lastSuccessfulScan = nil   // kein gültiger Scan
            updateIcon(state: .alert)
            showScanErrorDialog(msg)

        case .clean:
            NSLog("[VirusGuard] Scan sauber (exit \(result.exitCode), \(result.filesScanned) Dateien).")
            lastSuccessfulScan = Date()
            updateIcon(state: .idle)
            onScanCompleted?(result)

        case .infected:
            NSLog("[VirusGuard] \(result.findings.count) Fund(e) erkannt.")
            lastSuccessfulScan = Date()   // Scan war gültig, Funde sind Ergebnis
            updateIcon(state: .alert)
            onFindingsDetected?(result)
            onScanCompleted?(result)
        }
    }

    // MARK: - Scan-Fehler-Dialog

    /// Zeigt einen modalen Dialog bei Scan-Fehlern (Exit >= 2, Abbruch).
    private func showScanErrorDialog(_ message: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Scan konnte nicht vollständig abgeschlossen werden"
        alert.informativeText = "VirusGuard meldet KEINEN sauberen Status.\n\n\(message)"
        alert.addButton(withTitle: "OK")
        NSApp.activate(ignoringOtherApps: true)
        _ = alert.runModal()
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

        // Tooltip – ehrlich: „periodischer Scan“, NICHT „Echtzeitschutz“.
        if state == .scanning {
            statusItem.button?.toolTip = "VirusGuard scannt gerade …"
        } else if let secs = nextScanIn {
            let mins = Int(secs) / 60
            statusItem.button?.toolTip = "VirusGuard – periodischer Scan (kein Echtzeitschutz). Nächster in ca. \(mins) Min."
        } else {
            statusItem.button?.toolTip = "VirusGuard – aktiv (periodischer Scan, kein Echtzeitschutz)"
        }
    }

    private func setupMenu() {
        let menu = NSMenu()
        menu.autoenablesItems = true

        // --- Status-Block: ehrliche Informationen über Abdeckung & Alter ---
        let lastScanItem = NSMenuItem(title: statusMenuLine_lastScan(), action: nil, keyEquivalent: "")
        lastScanItem.isEnabled = false
        menu.addItem(lastScanItem)

        let coverageItem = NSMenuItem(title: statusMenuLine_coverage(), action: nil, keyEquivalent: "")
        coverageItem.isEnabled = false
        menu.addItem(coverageItem)

        let sigItem = NSMenuItem(title: statusMenuLine_signatures(), action: nil, keyEquivalent: "")
        sigItem.isEnabled = false
        menu.addItem(sigItem)

        menu.addItem(NSMenuItem.separator())

        let scanItem = NSMenuItem(title: "Jetzt scannen", action: #selector(scanNowMenu), keyEquivalent: "s")
        let configItem = NSMenuItem(title: "Einstellungen …", action: #selector(openConfig), keyEquivalent: ",")
        let quitItem = NSMenuItem(title: "VirusGuard beenden", action: #selector(quit), keyEquivalent: "q")

        // WICHTIG: ohne target sind die Items bei einer reinen Menüleisten-App
        // (kein Fenster/responder chain) ausgegraut.
        [scanItem, configItem, quitItem].forEach { $0.target = self }

        let updateSigsItem = NSMenuItem(title: "Signaturen aktualisieren …", action: #selector(updateSignaturesMenu), keyEquivalent: "u")
        updateSigsItem.target = self

        menu.addItem(scanItem)
        menu.addItem(updateSigsItem)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(configItem)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(quitItem)
        menu.delegate = self
        statusItem.menu = menu
    }

    /// Menüzeile: Zeitpunkt des letzten erfolgreichen Scans.
    private func statusMenuLine_lastScan() -> String {
        if let d = lastSuccessfulScan {
            let fmt = DateFormatter()
            fmt.locale = Locale(identifier: "de_DE")
            fmt.dateFormat = "dd.MM. HH:mm"
            let age = Int(Date().timeIntervalSince(d))
            let ageStr: String
            if age < 60 { ageStr = "gerade" }
            else if age < 3600 { ageStr = "vor \(age/60) Min." }
            else { ageStr = "vor \(age/3600) Std." }
            return "Letzter erfolgreicher Scan: \(fmt.string(from: d)) (\(ageStr))"
        }
        return "Letzter erfolgreicher Scan: noch keiner"
    }

    /// Menüzeile: Abdeckung – welche Pfade gescannt werden (eingeschränkt!).
    private func statusMenuLine_coverage() -> String {
        let names = config.scanPaths.map { ($0 as NSString).lastPathComponent }
        return "Abdeckung: \(names.joined(separator: ", "))"
    }

    /// Menüzeile: Signatur-Alter. Warnt bei veralteten/fehlenden Signaturen.
    private func statusMenuLine_signatures() -> String {
        if signatureManager.isUpdating {
            return "🔄 Signaturen: Aktualisierung läuft …"
        }
        if let d = lastSignatureUpdate {
            let age = Date().timeIntervalSince(d)
            if age > SignatureUpdateManager.staleInterval {
                let days = Int(age / 86400)
                return "⚠️ Signaturen veraltet (letztes Update vor \(days) Tag(en))"
            }
            return "Signaturen: aktuell"
        }
        return "⚠️ Keine Signaturen gefunden – bitte aktualisieren"
    }

    @objc private func scanNowMenu() { scanNow() }

    /// Löst ein Signatur-Update via freshclam aus (nicht-blockierend).
    /// Zeigt eine Erfolg/Misserfolg-Meldung, sobald freshclam endet.
    @objc private func updateSignaturesMenu() {
        guard !signatureManager.isUpdating else {
            let a = NSAlert()
            a.alertStyle = .informational
            a.messageText = "Aktualisierung läuft bereits"
            a.informativeText = "freshclam ist bereits aktiv. Bitte warten."
            a.addButton(withTitle: "OK")
            NSApp.activate(ignoringOtherApps: true)
            _ = a.runModal()
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        // Hinweis-Fenster: Update läuft.
        let info = NSAlert()
        info.alertStyle = .informational
        info.messageText = "Signaturen werden aktualisiert …"
        info.informativeText = "freshclam läuft im Hintergrund. Diese Meldung schließt automatisch, sobald das Update beendet ist."
        info.addButton(withTitle: "Im Hintergrund ausführen")
        _ = info.runModal()

        signatureManager.runFreshclam { [weak self] success, detail in
            guard let self = self else { return }
            // Nach Abschluss DB-Datum neu ermitteln.
            self.lastSignatureUpdate = self.signatureManager.lastSignatureUpdate()
            self.setupMenu()

            let a = NSAlert()
            a.alertStyle = success ? .informational : .warning
            a.messageText = success ? "Signaturen aktualisiert" : "Aktualisierung fehlgeschlagen"
            a.informativeText = detail
            a.addButton(withTitle: "OK")
            NSApp.activate(ignoringOtherApps: true)
            _ = a.runModal()
        }
    }

    @objc private func openConfig() {
        // Aktuelle Config neu laden (falls extern geändert) und Fenster öffnen.
        config = VirusGuardConfig.load()
        let w = ConfigWindow(config: config) { [weak self] newConfig in
            guard let self = self else { return }
            self.config = newConfig
            self.scanner = Scanner(config: newConfig)
            self.signatureManager = SignatureUpdateManager(config: newConfig)
            self.lastSignatureUpdate = self.signatureManager.lastSignatureUpdate()
            // Timer neu planen mit neuen Intervallen
            self.scheduleNextScan()
            // Menü neu aufbauen, damit Abdeckungs-Zeile aktuell ist.
            self.setupMenu()
            NSLog("[VirusGuard] Konfiguration aktualisiert.")
        }
        configWindow = w
        w.show()
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }
}
