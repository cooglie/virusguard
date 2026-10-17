import Foundation

/// Ergebnis eines Scan-Durchlaufs.
struct ScanResult {
    /// Gefundene Funde: (Pfad zur infizierten Datei, Name der Signatur).
    let findings: [(path: String, signature: String)]
    /// Roh-Ausgabe von clamscan (für Logs/debug).
    let rawOutput: String
    /// Exit-Code von clamscan (0 = sauber, 1 = Fund, 2+ = Fehler).
    let exitCode: Int
    /// true, wenn clamscan gar nicht erst lief (z.B. Binary fehlt).
    let engineError: String?
    /// Anzahl geprüfter Dateien (für Statistik).
    let filesScanned: Int
    /// Scan-Dauer in Sekunden.
    let durationSeconds: Double
}

/// Führt den eigentlichen Virenscan via ClamAV aus und stößt XProtect-Updates an.
final class Scanner {

    private let config: VirusGuardConfig
    private let queue = DispatchQueue(label: "virusguard.scanner", qos: .utility)

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

        // 2) ClamAV Binary prüfen – ggf. automatisch suchen
        var clamPath = config.clamScanPath
        if clamPath.isEmpty || !FileManager.default.isExecutableFile(atPath: clamPath) {
            if let found = ClamAVLocator.findClamScan() {
                clamPath = found
                // Gefundenen Pfad in der Config persistieren (einmalig)
                var cfg = config
                cfg.clamScanPath = found
                cfg.save()
            } else {
                return ScanResult(findings: [],
                                  rawOutput: "",
                                  exitCode: -1,
                                  engineError: ClamAVLocator.installHint(),
                                  filesScanned: 0,
                                  durationSeconds: 0)
            }
        }

        // 2b) ClamAV-Datenbank prüfen – ggf. automatisch suchen
        var dbPath = config.clamDatabase
        if dbPath.isEmpty || !FileManager.default.fileExists(atPath: dbPath) {
            if let found = ClamAVLocator.findDatabase() {
                dbPath = found
                var cfg = config
                cfg.clamDatabase = found
                cfg.save()
            }
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
        args += expanded

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: clamPath)
        proc.arguments = args

        let outPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = Pipe()   // ignorieren

        do {
            try proc.run()
        } catch {
            return ScanResult(findings: [],
                              rawOutput: "",
                              exitCode: -1,
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

        let duration = Date().timeIntervalSince(startTime)
        return ScanResult(findings: findings,
                          rawOutput: allOutput,
                          exitCode: Int(proc.terminationStatus),
                          engineError: nil,
                          filesScanned: scanned,
                          durationSeconds: duration)
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
    private func triggerXProtect() {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/softwareupdate")
        proc.arguments = ["--background"]
        proc.standardOutput = Pipe()
        proc.standardError = Pipe()
        try? proc.run()
        proc.waitUntilExit()
    }

    /// Verschiebt eine infizierte Datei in den Quarantäne-Ordner.
    /// Gibt true zurück bei Erfolg.
    @discardableResult
    func quarantine(file path: String) -> Bool {
        config.ensureQuarantineFolderExists()
        let dest = NSString(string: config.quarantineFolder).expandingTildeInPath
        let fm = FileManager.default

        let srcURL = URL(fileURLWithPath: path)
        let destURL = URL(fileURLWithPath: dest)
            .appendingPathComponent(srcURL.lastPathComponent)
        do {
            // Bewegen (nicht kopieren) → Datei verschwindet aus Originalort
            if fm.fileExists(atPath: destURL.path) {
                try fm.removeItem(at: destURL)
            }
            try fm.moveItem(at: srcURL, to: destURL)
            return true
        } catch {
            return false
        }
    }
}
