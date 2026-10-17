import Foundation

/// Helfer, um die clamscan-Binary automatisch zu finden.
enum ClamAVLocator {

    /// Sucht clamscan in typischen Installationspfaden und via PATH-Auflösung.
    /// Gibt den ersten gefundenen Pfad zurück, sonst nil.
    static func findClamScan() -> String? {
        // 1) Bekannte Installationsorte (Intel + Apple Silicon + Homebrew in Home)
        let candidates = [
            "/usr/local/clamav/bin/clamscan",      // offizielles ClamAV-PKG (Cisco)
            "/usr/local/bin/clamscan",            // klassisches Intel-Homebrew
            "/opt/homebrew/bin/clamscan",         // Apple Silicon Homebrew
            "\(homeDir())/homebrew/brew/bin/clamscan",  // Homebrew im Home-Verzeichnis
            "/usr/local/Homebrew/bin/clamscan",
            "/opt/local/bin/clamscan",            // MacPorts
            "/usr/bin/clamscan"
        ]

        let fm = FileManager.default
        for path in candidates {
            if fm.isExecutableFile(atPath: path) {
                return path
            }
        }

        // 2) `which clamscan` in einer Shell ausführen (PATH des Nutzers)
        if let fromPath = resolveWhich() {
            return fromPath
        }

        return nil
    }

    /// True, wenn clamscan irgendwo gefunden wird.
    static func isAvailable() -> Bool {
        return findClamScan() != nil
    }

    /// Sucht das ClamAV-Datenbank-Verzeichnis (main.cvd/daily.cvd).
    /// Reihenfolge: Nutzer-Home (~/.clamav/db), offizielles PKG, Homebrew.
    static func findDatabase() -> String? {
        let candidates = [
            "\(homeDir())/.clamav/db",                   // VirusGuard-Nutzer-Setup
            "/usr/local/clamav/share/clamav",            // offizielles ClamAV-PKG (Cisco)
            "/usr/local/share/clamav",                   // Intel-Homebrew
            "/opt/homebrew/share/clamav",                // Apple Silicon Homebrew
            "\(homeDir())/homebrew/brew/share/clamav"    // Homebrew im Home
        ]
        let fm = FileManager.default
        for path in candidates {
            if fm.fileExists(atPath: path) {
                // Prüfen, ob tatsächlich eine .cvd-Datei liegt
                if let entries = try? fm.contentsOfDirectory(atPath: path) {
                    if entries.contains(where: { $0.hasSuffix(".cvd") || $0.hasSuffix(".cld") }) {
                        return path
                    }
                }
            }
        }
        return nil
    }

    /// Liefert einen hilfreichen Installationshinweis für den Nutzer.
    static func installHint() -> String {
        return """
        ClamAV (clamscan) wurde nicht gefunden.

        Bitte ClamAV installieren, z. B. mit Homebrew:
            brew install clamav

        Oder manuell laden: https://www.clamav.net/downloads

        Danach VirusGuard neu starten.
        """
    }

    // MARK: - Internals

    private static func homeDir() -> String {
        return NSHomeDirectory()
    }

    private static func resolveWhich() -> String? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        proc.arguments = ["clamscan"]

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()

        do {
            try proc.run()
            proc.waitUntilExit()
            guard proc.terminationStatus == 0 else { return nil }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let raw = String(data: data, encoding: .utf8) ?? ""
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            // which kann mehrere Pfade liefern (eine pro Zeile) → ersten nehmen
            let first = trimmed.split(separator: "\n").first.map(String.init) ?? trimmed
            if !first.isEmpty && FileManager.default.isExecutableFile(atPath: first) {
                return first
            }
            return nil
        } catch {
            return nil
        }
    }
}
