import Foundation

/// Drei getrennte Scan-Zustände plus Engine-Fehler.
/// Ein fehlerhafter Scan darf niemals als „sauber“ gelten.
enum ScanStatus: Equatable {
    /// Exit-Code 0, keine Funde – vollständig abgeschlossener, sauberer Scan.
    case clean
    /// Exit-Code 1, Funde vorhanden.
    case infected
    /// Exit-Code >= 2: clamscan lief, aber mit Fehlern (korrupte DB,
    /// nicht lesbare Dateien, abgebrochen, unvollständig). NIEMALS als sauber darstellen.
    case scanError(String)
    /// clamscan konnte gar nicht erst laufen (Binary fehlt, Start fehlgeschlagen).
    case engineError(String)
}

/// Ergebnis eines Scan-Durchlaufs.
struct ScanResult {
    /// Gefundene Funde: (Pfad zur infizierten Datei, Name der Signatur).
    let findings: [(path: String, signature: String)]
    /// Roh-Ausgabe von clamscan stdout (für Logs/debug).
    let rawOutput: String
    /// stderr von clamscan (Fehlermeldungen, Warnungen).
    let stderrOutput: String
    /// Exit-Code von clamscan (0 = sauber, 1 = Fund, 2+ = Fehler).
    /// Bei Signal-Abbruch: 128 + Signal-Nummer.
    let exitCode: Int
    /// true, wenn clamscan durch ein Signal abgebrochen wurde (SIGTERM/SIGKILL).
    let aborted: Bool
    /// true, wenn clamscan gar nicht erst lief (z.B. Binary fehlt).
    let engineError: String?
    /// Anzahl geprüfter Dateien (für Statistik).
    let filesScanned: Int
    /// Scan-Dauer in Sekunden.
    let durationSeconds: Double

    /// Klassifiziert das Ergebnis in einen der vier ScanStatus-Zustände.
    /// WICHTIG: ein fehlerhafter/abgebrochener Scan wird NIEMALS als .clean gemeldet.
    var status: ScanStatus {
        if let err = engineError {
            return .engineError(err)
        }
        if aborted {
            return .scanError("Scan wurde abgebrochen (Signal empfangen).")
        }
        // Exit-Code-Auswertung clamscan-Dokumentation:
        //   0 = kein Virus, 1 = Virus gefunden, 2+ = Fehler.
        // Bei Signal-Termination ist exitCode >= 128 → ebenfalls Fehler.
        if exitCode == 0 && findings.isEmpty {
            return .clean
        }
        if exitCode == 1 || !findings.isEmpty {
            return .infected
        }
        // Exit-Code >= 2 (oder andere unerwartete Codes) ohne sauberen Abschluss:
        let detail = stderrOutput.trimmingCharacters(in: .whitespacesAndNewlines)
        return .scanError(detail.isEmpty
            ? "clamscan meldete Fehler (Exit-Code \(exitCode))."
            : "clamscan meldete Fehler (Exit-Code \(exitCode)): \(detail)")
    }
}


/// Führt den eigentlichen Virenscan via ClamAV aus und stößt XProtect-Updates an.
final class Scanner {

    private let config: VirusGuardConfig
    private let queue = DispatchQueue(label: "virusguard.scanner", qos: .utility)
    /// Referenz auf den laufenden clamscan-Prozess (für Abbruch).
    private var currentProcess: Process?
    /// Sichere Quarantäne-Verwaltung (wird vom AppDelegate injiziert).
    weak var quarantineManager: QuarantineManager?

    init(config: VirusGuardConfig) {
        self.config = config
    }

    /// Startet den Scan asynchron.
    /// `progress`: wird auf dem Main-Thread aufgerufen mit (scanned, total, currentFile).
    /// `finding`:  wird auf dem Main-Thread aufgerufen, sobald clamscan einen Fund
    ///             meldet (Pfad + Signatur) – noch während der Scan läuft.
    func scan(progress: @escaping (Int, Int?, String?) -> Void,
              finding: @escaping (String, String) -> Void = { _, _ in },
              completion: @escaping (ScanResult) -> Void) {
        queue.async { [weak self] in
            guard let self = self else { return }
            let result = self.runScanSync(progress: progress, finding: finding)
            DispatchQueue.main.async { completion(result) }
        }
    }

    // MARK: - Internals

    private func runScanSync(progress: @escaping (Int, Int?, String?) -> Void,
                              finding: @escaping (String, String) -> Void) -> ScanResult {
        let startTime = Date()

        // 1) Optional XProtect-Update anstoßen (läuft asynchron im Hintergrund, wir warten nicht)
        if config.triggerXProtectUpdate {
            DispatchQueue.global(qos: .background).async {
                self.triggerXProtect()
            }
        }

        // 2) ClamAV Binary prüfen – ggf. automatisch suchen. Strikt validieren:
        //    nur ein tatsächlich existierendes, ausführbares Binary ist akzeptiert.
        var clamPath = config.clamScanPath
        if !clamPath.isEmpty {
            // Kanonisieren + Existenz prüfen – manipulierten/ungültigen Pfad ablehnen.
            let resolved = resolveClamPath(clamPath)
            if FileManager.default.isExecutableFile(atPath: resolved) {
                clamPath = resolved
            } else {
                return ScanResult(findings: [],
                                  rawOutput: "",
                                  stderrOutput: "",
                                  exitCode: -1,
                                  aborted: false,
                                  engineError: "Konfigurierter clamscan-Pfad ist nicht ausführbar: \(clamPath)",
                                  filesScanned: 0,
                                  durationSeconds: 0)
            }
        }
        if clamPath.isEmpty {
            if let found = ClamAVLocator.findClamScan() {
                clamPath = found
                var cfg = config
                cfg.clamScanPath = found
                cfg.save()
            } else {
                return ScanResult(findings: [],
                                  rawOutput: "",
                                  stderrOutput: "",
                                  exitCode: -1,
                                  aborted: false,
                                  engineError: ClamAVLocator.installHint(),
                                  filesScanned: 0,
                                  durationSeconds: 0)
            }
        }

        // 2b) ClamAV-Datenbank prüfen. Ohne gültige DB ist ein „sauber"-Ergebnis
        //    wertlos → das wird als Engine-Fehler gemeldet, nicht stillschweigend akzeptiert.
        var dbPath = config.clamDatabase
        if !dbPath.isEmpty {
            if !ClamAVLocator.databaseIsValid(at: dbPath) {
                // Versuch, eine gültige DB zu finden.
                if let found = ClamAVLocator.findDatabase() {
                    dbPath = found
                    var cfg = config
                    cfg.clamDatabase = found
                    cfg.save()
                } else {
                    return ScanResult(findings: [],
                                      rawOutput: "",
                                      stderrOutput: "",
                                      exitCode: -1,
                                      aborted: false,
                                      engineError: "ClamAV-Signaturdatenbank fehlt oder ist unbrauchbar. Bitte freshclam ausführen.",
                                      filesScanned: 0,
                                      durationSeconds: 0)
                }
            }
        } else if let found = ClamAVLocator.findDatabase() {
            dbPath = found
            var cfg = config
            cfg.clamDatabase = found
            cfg.save()
        } else {
            return ScanResult(findings: [],
                              rawOutput: "",
                              stderrOutput: "",
                              exitCode: -1,
                              aborted: false,
                              engineError: "Keine ClamAV-Signaturdatenbank gefunden. Bitte freshclam ausführen.",
                              filesScanned: 0,
                              durationSeconds: 0)
        }

        // 3) Pfade auflösen (~ → Home)
        let expanded = config.scanPaths.map { NSString(string: $0).expandingTildeInPath }

        // 4) Dateien vorab zählen (für Prozentanzeige). Kann bei riesigen Verzeichnissen
        //    etwas dauern – falls 0, arbeiten wir mit unbestimmter Anzeige weiter.
        let totalFiles = countFiles(in: expanded)
        DispatchQueue.main.async { progress(0, totalFiles > 0 ? totalFiles : nil, nil) }

        // 5) clamscan mit --verbose aufrufen → jede Datei wird als "Scanning <pfad>" ausgegeben.
        //    --recursive (-r) ist Pflicht: ohne scannt clamscan nur die direkt
        //    im Ordner liegenden Dateien, keine Unterordner → illusorisch wenige Treffer.
        var args = ["--infected", "--no-summary", "--verbose", "--recursive"]
        if !dbPath.isEmpty {
            args += ["--database", dbPath]
        }
        // Quarantäne-Ordner vom Scan ausschließen – verhindert, dass bereits
        // quarantänierte Dateien erneut gemeldet werden (Endlosschleife / Doppelzählung).
        let qPath = NSString(string: config.quarantineFolder).expandingTildeInPath
        args += ["--exclude", qPath]
        args += expanded

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: clamPath)
        proc.arguments = args

        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe   // wird ausgewertet

        // Prozess-Referenz speichern, damit ein laufender Scan abgebrochen werden kann.
        currentProcess = proc
        defer { currentProcess = nil }

        do {
            try proc.run()
        } catch {
            return ScanResult(findings: [],
                              rawOutput: "",
                              stderrOutput: "",
                              exitCode: -1,
                              aborted: false,
                              engineError: "Konnte clamscan nicht starten: \(error.localizedDescription)",
                              filesScanned: 0,
                              durationSeconds: 0)
        }

        // 6) stdout zeilenweise streamen → Live-Fortschritt
        var findings: [(String, String)] = []
        var scanned = 0
        var allOutput = ""

        let readHandle = outPipe.fileHandleForReading
        var buffer = Data()

        // readabilityHandler feuert auf einer Hintergrund-Queue, sobald Daten anliegen.
        let progressLock = NSLock()
        let scanDone = DispatchSemaphore(value: 0)

        readHandle.readabilityHandler = { handle in
            let chunk = handle.availableData
            if chunk.isEmpty {
                // EOF
                handle.readabilityHandler = nil
                scanDone.signal()
                return
            }
            buffer.append(chunk)

            // Vollständige Zeilen verarbeiten
            while let nlIndex = buffer.firstIndex(of: 0x0A) {
                let lineData = buffer.subdata(in: 0..<nlIndex)
                buffer.removeSubrange(0...nlIndex)
                guard let line = String(data: lineData, encoding: .utf8) else { continue }
                allOutput += line + "\n"

                if line.hasPrefix("Scanning ") {
                    let path = String(line.dropFirst("Scanning ".count)).trimmingCharacters(in: .whitespaces)
                    progressLock.lock()
                    scanned += 1
                    let s = scanned
                    progressLock.unlock()
                    DispatchQueue.main.async {
                        progress(s, totalFiles > 0 ? totalFiles : nil, path)
                    }
                } else if line.hasSuffix(" FOUND") {
                    let body = String(line.dropLast(" FOUND".count))
                    if let colon = body.range(of: ": ") {
                        let p = String(body[body.startIndex..<colon.lowerBound])
                        let sig = String(body[colon.upperBound...])
                        findings.append((p, sig))
                        DispatchQueue.main.async {
                            finding(p, sig)
                        }
                    }
                }
            }
        }

        proc.terminationHandler = { _ in
            // Sicherstellen, dass der Rest des Puffers gelesen wird
            readHandle.readabilityHandler = nil
            let rest = readHandle.readDataToEndOfFile()
            if !rest.isEmpty {
                buffer.append(rest)
                let remaining = String(data: buffer, encoding: .utf8) ?? ""
                allOutput += remaining
                for line in remaining.split(separator: "\n") {
                    let s = String(line)
                    if s.hasSuffix(" FOUND") {
                        let body = String(s.dropLast(" FOUND".count))
                        if let colon = body.range(of: ": ") {
                            let p = String(body[body.startIndex..<colon.lowerBound])
                            let sig = String(body[colon.upperBound...])
                            findings.append((p, sig))
                            DispatchQueue.main.async {
                                finding(p, sig)
                            }
                        }
                    }
                }
            }
            scanDone.signal()
        }

        scanDone.wait()

        // stderr auslesen – enthält Fehlermeldungen bei korrupter DB,
        // nicht lesbaren Dateien, abgebrochenen Scans usw.
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrStr = String(data: errData, encoding: .utf8) ?? ""

        // Signal-Abbruch erkennen (SIGTERM/SIGKILL vom Nutzer oder System).
        // terminationReason == .uncaughtSignal ODER exitCode >= 128.
        let termStatus = Int(proc.terminationStatus)
        let wasAborted = (proc.terminationReason == .uncaughtSignal) || (termStatus >= 128)

        let duration = Date().timeIntervalSince(startTime)

        // Nicht lesbare Dateien / Berechtigungsfehler im stderr protokollieren.
        if !stderrStr.isEmpty {
            for line in stderrStr.split(separator: "\n") {
                NSLog("[VirusGuard] clamscan stderr: \(line)")
            }
        }

        return ScanResult(findings: findings,
                          rawOutput: allOutput,
                          stderrOutput: stderrStr,
                          exitCode: termStatus,
                          aborted: wasAborted,
                          engineError: nil,
                          filesScanned: scanned,
                          durationSeconds: duration)
    }

    /// Bricht einen laufenden Scan ab (SIGTERM). Sicher, auch wenn gerade kein Scan läuft.
    func abortScan() {
        currentProcess?.terminate()
    }

    /// Kanonisiert einen Pfad (löst Symlinks/relative Anteile auf).
    private func resolveClamPath(_ path: String) -> String {
        let expanded = NSString(string: path).expandingTildeInPath
        // realpath über FileManager – falls nicht auflösbar, Original zurückgeben.
        if let rv = try? URL(fileURLWithPath: expanded).resourceValues(forKeys: [.canonicalPathKey]),
           let resolved = rv.canonicalPath {
            return resolved
        }
        return expanded
    }

    /// Zählt reguläre Dateien in den angegebenen Pfaden (rekursiv).
    private func countFiles(in paths: [String]) -> Int {
        let fm = FileManager.default
        var count = 0
        for path in paths {
            guard fm.fileExists(atPath: path) else { continue }
            var isDir: ObjCBool = false
            if fm.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue {
                if let enumerator = fm.enumerator(at: URL(fileURLWithPath: path),
                                                  includingPropertiesForKeys: [.isRegularFileKey],
                                                  options: [.skipsHiddenFiles]) {
                    for case let url as URL in enumerator {
                        if let vals = try? url.resourceValues(forKeys: [.isRegularFileKey]),
                           vals.isRegularFile == true {
                            count += 1
                        }
                    }
                }
            } else {
                count += 1
            }
        }
        return count
    }

    /// Stößt macOS-XProtect-Updates im Hintergrund an (nicht-blockierend).
    ///
    /// WICHTIG – Dokumentation der Grenzen:
    /// `softwareupdate --background` stößt allgemeine Hintergrund-Updates an und
    /// kann XProtect-Updates enthalten, liefert aber KEINE bestätigung, dass ein
    /// XProtect-Update tatsächlich installiert wurde. Der Exit-Code zeigt nur an,
    /// ob der *Aufruf* von softwareupdate erfolgreich war, nicht ob XProtect
    /// aktualisiert wurde. XProtect wird von macOS selbst verwaltet.
    ///
    /// Diese Funktion wertet daher den Exit-Code aus und protokolliert
    /// Fehler/Berechtigungsprobleme – behandelt einen erfolgreichen Start aber
    /// NICHT als „XProtect erfolgreich aktualisiert".
    private func triggerXProtect() {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/softwareupdate")
        proc.arguments = ["--background"]
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe

        do {
            try proc.run()
        } catch {
            NSLog("[VirusGuard] XProtect-Update konnte nicht gestartet werden: \(error.localizedDescription). Hinweis: ggf. sind Admin-Rechte nötig.")
            return
        }
        proc.waitUntilExit()

        let exitCode = Int(proc.terminationStatus)
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrStr = String(data: errData, encoding: .utf8) ?? ""

        if exitCode == 0 {
            NSLog("[VirusGuard] softwareupdate --background wurde ausgeführt (Exit 0). " +
                  "Hinweis: dies bestätigt nicht, dass XProtect aktualisiert wurde – macOS verwaltet XProtect selbst.")
        } else {
            NSLog("[VirusGuard] softwareupdate --background endete mit Exit-Code \(exitCode). " +
                  "Mögliche Ursache: fehlende Admin-Rechte. stderr: \(stderrStr.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }

    /// Verschiebt eine infizierte Datei SICHER in die Quarantäne über den
    /// QuarantineManager. Prüft Datei-Identität, verhindert Überschreiben,
    /// behandelt Symlinks. Gibt Erfolg/Meldung zurück.
    /// Signatur wird aus dem zuletzt gescannten Fund bezogen (falls bekannt).
    @discardableResult
    func quarantine(file path: String, signature: String = "(unbekannt)") -> Bool {
        guard let mgr = quarantineManager else {
            NSLog("[VirusGuard] QuarantineManager nicht konfiguriert – Verschieben abgelehnt.")
            return false
        }
        let result = mgr.quarantine(sourcePath: path, signature: signature)
        return result.success
    }
}
