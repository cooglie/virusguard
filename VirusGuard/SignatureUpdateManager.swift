import Foundation

/// Verwaltet ClamAV-Signatur-Updates (freshclam) und ermittelt das Alter der
/// installierten Signaturen. Update und Scan sind entkoppelt: ein Update-Lauf
/// blockiert keinen Scan und umgekehrt.
///
/// Ehrlichkeit über Grenzen:
/// - freshclam benötigt i.d.R. Schreibrechte auf das DB-Verzeichnis. Ohne diese
///   schlägt das Update fehl (wird protokolliert, nicht verschwiegen).
/// - Das „letzte Update"-Datum wird aus den DB-Dateien (main.cld/cvd,
///   daily.cld/cvd) ermittelt, nicht aus freshclam-Logs – so ist es auch nach
///   einem Neustart korrekt.
final class SignatureUpdateManager {

    /// Interval ab dem Signaturen als „veraltet" gelten (7 Tage).
    static let staleInterval: TimeInterval = 7 * 24 * 3600

    private let config: VirusGuardConfig
    private var runningProcess: Process?
    private let lock = NSLock()

    init(config: VirusGuardConfig) {
        self.config = config
    }

    /// Läuft gerade ein freshclam-Prozess?
    var isUpdating: Bool {
        lock.lock(); defer { lock.unlock() }
        return runningProcess?.isRunning ?? false
    }

    /// Ermittelt das Datum der jüngsten DB-Datei im konfigurierten DB-Verzeichnis.
    /// Liefert nil, wenn keine DB-Dateien gefunden werden.
    func lastSignatureUpdate() -> Date? {
        let dbDir = resolvedDBPath()
        guard !dbDir.isEmpty else { return nil }
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: dbDir) else { return nil }

        let dbSuffixes = ["main.cld", "main.cvd", "daily.cld", "daily.cvd",
                          "bytecode.cld", "bytecode.cvd", "safebrowsing.cld", "safebrowsing.cvd"]
        var newest: Date?
        for entry in entries {
            guard dbSuffixes.contains(entry.lowercased()) else { continue }
            let full = (dbDir as NSString).appendingPathComponent(entry)
            guard let attrs = try? fm.attributesOfItem(atPath: full) else { continue }
            // ClamAV-DBs werden beim Update neu geschrieben → Mod-Datum = Update.
            if let mod = attrs[.modificationDate] as? Date {
                if newest == nil || mod > newest! { newest = mod }
            }
        }
        return newest
    }

    /// True, wenn die Signaturen älter als `staleInterval` sind ODER unbekannt.
    func signaturesAreStale() -> Bool {
        guard let date = lastSignatureUpdate() else { return true }
        return Date().timeIntervalSince(date) > SignatureUpdateManager.staleInterval
    }

    /// Startet freshclam asynchron (nicht-blockierend). Liefert false, wenn
    /// freshclam nicht gefunden wird oder schon ein Update läuft.
    /// `completion` wird aufgerufen, sobald freshclam beendet ist (Haupt-Thread).
    @discardableResult
    func runFreshclam(completion: ((Bool, String) -> Void)? = nil) -> Bool {
        lock.lock()
        if runningProcess?.isRunning == true {
            lock.unlock()
            completion?(false, "freshclam läuft bereits.")
            return false
        }
        lock.unlock()

        guard let freshclam = ClamAVLocator.findFreshclam() else {
            completion?(false, "freshclam nicht gefunden. Bitte ClamAV installieren.")
            NSLog("[VirusGuard] freshclam nicht gefunden.")
            return false
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: freshclam)
        var args: [String] = ["--no-warnings"]   // Warnungen als Logs, nicht als Fehler
        let dbDir = resolvedDBPath()
        if !dbDir.isEmpty {
            args += ["--datadir", dbDir]
        }
        proc.arguments = args
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe

        do {
            try proc.run()
        } catch {
            let msg = "freshclam konnte nicht gestartet werden: \(error.localizedDescription). " +
                      "Hinweis: ggf. fehlen Schreibrechte auf das DB-Verzeichnis."
            NSLog("[VirusGuard] \(msg)")
            completion?(false, msg)
            return false
        }

        lock.lock()
        runningProcess = proc
        lock.unlock()

        NSLog("[VirusGuard] freshclam gestartet (datadir: \(dbDir)).")

        // Asynchron auf Beendigung warten – blockiert den Scan/Timer nicht.
        DispatchQueue.global(qos: .utility).async { [weak self] in
            proc.waitUntilExit()
            let exitCode = Int(proc.terminationStatus)
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let stderrStr = String(data: errData, encoding: .utf8) ?? ""
            let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            let stdoutStr = String(data: outData, encoding: .utf8) ?? ""

            self?.lock.lock()
            self?.runningProcess = nil
            self?.lock.unlock()

            let success = (exitCode == 0)
            let detail = success
                ? "Signaturen aktualisiert."
                : "freshclam endete mit Exit-Code \(exitCode). \(stderrStr.trimmingCharacters(in: .whitespacesAndNewlines))"
            NSLog("[VirusGuard] freshclam beendet (exit \(exitCode)). stdout: \(stdoutStr.suffix(200))")

            DispatchQueue.main.async {
                completion?(success, detail)
            }
        }
        return true
    }

    // MARK: - Privat

    private func resolvedDBPath() -> String {
        var p = config.clamDatabase
        if p.isEmpty, let found = ClamAVLocator.findDatabase() {
            p = found
        }
        return NSString(string: p).expandingTildeInPath
    }
}
