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
           let cfg = try? JSONDecoder().decode(VirusGuardConfig.self, from: data) {
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

    func save() {
        if let data = try? JSONEncoder().encode(self) {
            try? data.write(to: Self.configURL, options: .atomic)
        }
    }
}
