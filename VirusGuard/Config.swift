import Foundation

/// Konfiguration für VirusGuard.
/// Wird als JSON unter ~/Library/Application Support/VirusGuard/config.json gespeichert.
/// Bei erstem Start wird eine Standard-Config erzeugt.
struct VirusGuardConfig: Codable {
    /// Unteres Intervall-Limit in Sekunden.
    var minIntervalSeconds: Int = 600          // 10 Min
    /// Oberes Intervall-Limit in Sekunden.
    var maxIntervalSeconds: Int = 3600         // 60 Min
    /// Pfade, die gescannt werden.
    var scanPaths: [String] = ["~/Downloads", "~/Desktop"]
    /// Pfad zum clamscan Binary (ClamAV).
    /// Leer → wird beim App-Start automatisch gesucht (ClamAVLocator).
    var clamScanPath: String = ""
    /// Pfad zur freshclam-Datenbank (kann leer sein → Standard).
    var clamDatabase: String = ""
    /// Ordner für quarantäne verschobene Dateien.
    var quarantineFolder: String = "~/Desktop/Quarantine"
    /// XProtect-Updates im Hintergrund anstoßen (softwareupdate --background).
    var triggerXProtectUpdate: Bool = true
    /// true → beim nächsten Timer-Event nur einmal scannen, dann App beenden (Debug).
    var scanOnce: Bool = false

    static let `default` = VirusGuardConfig()

    static var configURL: URL {
        let fm = FileManager.default
        let dir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("VirusGuard", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("config.json")
    }

    static func load() -> VirusGuardConfig {
        let url = configURL
        if let data = try? Data(contentsOf: url),
           var cfg = try? JSONDecoder().decode(VirusGuardConfig.self, from: data) {
            let warnings = cfg.validate()
            if !warnings.isEmpty {
                for w in warnings { NSLog("[VirusGuard] Config-Warnung: \(w)") }
                cfg.save()   // korrigierte Config persistieren
            }
            cfg.ensureQuarantineFolderExists()
            return cfg
        }
        // Standard-Config erzeugen & speichern
        let cfg = VirusGuardConfig.default
        cfg.ensureQuarantineFolderExists()
        cfg.save()
        return cfg
    }

    /// Stellt sicher, dass der konfigurierte Quarantäne-Ordner existiert.
    /// Wird beim Config-Laden und vor jeder Quarantäne-Aktion aufgerufen.
    func ensureQuarantineFolderExists() {
        let dest = NSString(string: quarantineFolder).expandingTildeInPath
        try? FileManager.default.createDirectory(atPath: dest, withIntermediateDirectories: true)
    }

    /// Validiert und kanonisiert die Konfiguration. Wird beim Speichern und
    /// Laden aufgerufen. Liefert eine Liste von Warnungen zurück (leer = OK).
    /// Unzulässige Werte werden auf sichere Defaults zurückgesetzt.
    @discardableResult
    mutating func validate() -> [String] {
        var warnings: [String] = []

        // 1) Intervalle: min >= 1, max >= min.
        if minIntervalSeconds < 1 {
            warnings.append("Min. Intervall war < 1 – auf 1 korrigiert.")
            minIntervalSeconds = 1
        }
        if maxIntervalSeconds < minIntervalSeconds {
            warnings.append("Max. Intervall < Min. Intervall – auf Min korrigiert.")
            maxIntervalSeconds = minIntervalSeconds
        }
        // Obergrenze, um Ressourcenverschleiß zu vermeiden (24 h).
        if maxIntervalSeconds > 86400 {
            warnings.append("Max. Intervall > 24 h – auf 24 h korrigiert.")
            maxIntervalSeconds = 86400
        }

        // 2) Scan-Pfade: Tilde expandieren, Leere entfernen, kanonalisieren.
        var canonicalPaths: [String] = []
        for raw in scanPaths {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            let expanded = NSString(string: trimmed).expandingTildeInPath
            canonicalPaths.append(expanded)
        }
        if canonicalPaths.isEmpty {
            warnings.append("Keine Scan-Pfade – Standard (~/Downloads) gesetzt.")
            canonicalPaths = ["\(NSHomeDirectory())/Downloads"]
        }
        scanPaths = canonicalPaths

        // 3) clamScanPath: wenn gesetzt, muss es eine ausführbare Datei sein.
        if !clamScanPath.isEmpty {
            let expanded = NSString(string: clamScanPath).expandingTildeInPath
            if !FileManager.default.isExecutableFile(atPath: expanded) {
                warnings.append("clamscan-Pfad nicht ausführbar – wird beim Start neu gesucht.")
                clamScanPath = ""
            } else {
                clamScanPath = expanded
            }
        }

        // 4) clamDatabase: wenn gesetzt, muss das Verzeichnis existieren.
        if !clamDatabase.isEmpty {
            let expanded = NSString(string: clamDatabase).expandingTildeInPath
            if !FileManager.default.fileExists(atPath: expanded) {
                warnings.append("ClamAV-DB-Pfad existiert nicht – wird beim Start neu gesucht.")
                clamDatabase = ""
            } else {
                clamDatabase = expanded
            }
        }

        // 5) Quarantäne-Ordner: kanonalisieren + Überschneidung mit Scan-Pfad erkennen.
        let qExpanded = NSString(string: quarantineFolder).expandingTildeInPath
        quarantineFolder = qExpanded
        for sp in scanPaths {
            let scanResolved = resolveCanonical(sp)
            let qResolved = resolveCanonical(qExpanded)
            // Überschneidung: Quarantäne liegt innerhalb eines Scan-Pfads ODER umgekehrt.
            if qResolved.hasPrefix(scanResolved + "/") || qResolved == scanResolved {
                warnings.append("⚠️ Quarantäne-Ordner liegt im Scan-Pfad – wird beim Scannen ignoriert.")
                break
            }
            if scanResolved.hasPrefix(qResolved + "/") {
                warnings.append("⚠️ Scan-Pfad liegt im Quarantäne-Ordner – potenzielle Endlosschleife.")
                break
            }
        }

        return warnings
    }

    /// Kanonisiert einen Pfad (realpath, löst Symlinks auf). Fallback: expandiert.
    private func resolveCanonical(_ path: String) -> String {
        if let rv = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.canonicalPathKey]),
           let resolved = rv.canonicalPath {
            return resolved
        }
        return path
    }

    func save() {
        var cfg = self
        _ = cfg.validate()
        if let data = try? JSONEncoder().encode(cfg) {
            try? data.write(to: Self.configURL, options: .atomic)
        }
    }
}
