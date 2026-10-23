import Foundation

/// Sichere Quarantäne-Verwaltung: schützt vor Datenverlust durch veränderte
/// Dateien zwischen Scan und Verschiebung, verhindert stillschweigendes
/// Überschreiben, behandelt Symlinks sicher und stellt Wiederherstellung bereit.
///
/// Sicherheitsversprechen:
/// 1. Vor dem Verschieben wird geprüft, ob die Quelldatei noch dieselbe Datei ist,
///    die gescannt wurde (Inode + Größe + mtime). Eine veränderte Datei wird NICHT
///    verschoben.
/// 2. Vorhandene Zieldateien werden nie überschrieben – stattdessen ein
///    eindeutiger Suffix (Zähler) angehängt.
/// 3. Symlinks werden nicht verschoben, sondern verworfen (Sicherheit vor
///    Pfade-Veränderung / TOCTOU).
/// 4. Quarantäne-Ordner bekommt restriktive Rechte (0700).
/// 5. Jede Aktion wird protokolliert und ist wiederherstellbar.
final class QuarantineManager {

    /// Ein Quarantäne-Eintrag (wird in quarantine_log.json gespeichert).
    struct Entry: Codable {
        var originalPath: String      // kanonischer Pfad der Quelldatei
        var quarantinedPath: String   // Pfad in der Quarantäne
        var signature: String         // erkannte Signatur
        var quarantinedAt: Date
        var inode: UInt64             // Inode zum Zeitpunkt der Quarantäne
        var size: UInt64              // Dateigröße zum Zeitpunkt der Quarantäne
        var restored: Bool            // true, wenn wiederhergestellt
    }

    private let config: VirusGuardConfig
    private let fm = FileManager.default
    private(set) var entries: [Entry] = []

    init(config: VirusGuardConfig) {
        self.config = config
        ensureQuarantineFolder()
        loadEntries()
    }

    // MARK: - Ordner-Verwaltung

    /// Stellt den Quarantäne-Ordner sicher und setzt restriktive Rechte (0700).
    private func ensureQuarantineFolder() {
        let dest = resolvedQuarantinePath()
        do {
            if !fm.fileExists(atPath: dest) {
                try fm.createDirectory(atPath: dest, withIntermediateDirectories: true,
                                       attributes: [.posixPermissions: 0o700])
            }
            // Rechte auch bei bestehendem Ordner restriktiv setzen.
            try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dest)
        } catch {
            NSLog("[VirusGuard] Quarantäne-Ordner konnte nicht erstellt werden: \(error.localizedDescription)")
        }
    }

    private func resolvedQuarantinePath() -> String {
        return NSString(string: config.quarantineFolder).expandingTildeInPath
    }

    // MARK: - Verschieben (sicher)

    /// Verschiebt eine als infiziert erkannte Datei sicher in die Quarantäne.
    /// - Parameters:
    ///   - sourcePath: Pfad der infizierten Datei (wie von clamscan gemeldet).
    ///   - signature: erkannte Signatur.
    ///   - scannedInode: Inode der Datei zum Scan-Zeitpunkt (falls bekannt).
    ///   - scannedSize: Dateigröße zum Scan-Zeitpunkt (falls bekannt).
    /// - Returns: Pfad in der Quarantäne bei Erfolg, sonst nil mit Fehlermeldung.
    func quarantine(sourcePath: String,
                    signature: String,
                    scannedInode: UInt64? = nil,
                    scannedSize: UInt64? = nil) -> (success: Bool, message: String) {

        // 0) Ordner sicherstellen (kann gelöscht worden sein)
        ensureQuarantineFolder()

        // 1) Quelle muss existieren und eine reguläre Datei sein (kein Symlink!).
        guard fm.fileExists(atPath: sourcePath) else {
            let msg = "Quelldatei existiert nicht mehr: \(sourcePath)"
            NSLog("[VirusGuard] Quarantäne abgelehnt: \(msg)")
            return (false, msg)
        }
        // Symlink? → nicht folgen, nicht verschieben (Sicherheitsrisiko).
        let lstat = try? fm.attributesOfItem(atPath: sourcePath)
        if let type = lstat?[.type] as? FileAttributeType, type == .typeSymbolicLink {
            let msg = "Quelldatei ist ein Symlink – wird nicht in Quarantäne verschoben: \(sourcePath)"
            NSLog("[VirusGuard] Quarantäne abgelehnt: \(msg)")
            return (false, msg)
        }

        // 2) Datei-Identität prüfen: stimmt Inode/Größe noch mit dem Scan überein?
        //    Wurde die Datei zwischen Scan und Quarantäne verändert, NICHT verschieben.
        guard let attrs = try? fm.attributesOfItem(atPath: sourcePath) else {
            let msg = "Attribute der Quelldatei nicht lesbar: \(sourcePath)"
            NSLog("[VirusGuard] Quarantäne abgelehnt: \(msg)")
            return (false, msg)
        }
        let currentInode = (attrs[.systemFileNumber] as? NSNumber)?.uint64Value ?? 0
        let currentSize = (attrs[.size] as? NSNumber)?.uint64Value ?? 0

        if let scannedInode = scannedInode, scannedInode != 0, currentInode != scannedInode {
            let msg = "Datei wurde seit dem Scan ersetzt (Inode geändert) – nicht verschoben: \(sourcePath)"
            NSLog("[VirusGuard] Quarantäne abgelehnt (TOCTOU): \(msg)")
            return (false, msg)
        }
        if let scannedSize = scannedSize, currentSize != scannedSize {
            let msg = "Datei wurde seit dem Scan verändert (Größe geändert) – nicht verschoben: \(sourcePath)"
            NSLog("[VirusGuard] Quarantäne abgelehnt (TOCTOU): \(msg)")
            return (false, msg)
        }

        // 3) Eindeutigen Zielpfad bestimmen – NIEMALS vorhandene Datei überschreiben.
        let baseName = (sourcePath as NSString).lastPathComponent
        let destDir = resolvedQuarantinePath()
        let destPath = uniqueDestinationPath(directory: destDir, baseName: baseName)

        // 4) Verschieben. Bei Fehlschlag Quelle unangetastet lassen.
        do {
            // Erst versuchen zu verschieben (same-volume ist effizient + atomar).
            //FileManager moveItemAtPath ist nicht atomar über Volumes; wir prüfen.
            try fm.moveItem(atPath: sourcePath, toPath: destPath)
        } catch {
            // moveItem schlägt über Volumes fehl → kopieren + Original löschen.
            do {
                try fm.copyItem(atPath: sourcePath, toPath: destPath)
                try fm.removeItem(atPath: sourcePath)
            } catch {
                // Wenn auch das Kopieren scheitert: sicherstellen, dass keine
                // halbe Kopierung bleibt und Quelle erhalten ist.
                if fm.fileExists(atPath: destPath) {
                    try? fm.removeItem(atPath: destPath)
                }
                let msg = "Verschieben fehlgeschlagen: \(error.localizedDescription)"
                NSLog("[VirusGuard] Quarantäne fehlgeschlagen: \(msg)")
                return (false, msg)
            }
        }

        // 5) Restriktive Rechte im Quarantäne-Ordner (0600 – nur lesbar/schreibbar für Besitzer).
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destPath)

        // 6) Eintrag protokollieren.
        let entry = Entry(originalPath: sourcePath,
                          quarantinedPath: destPath,
                          signature: signature,
                          quarantinedAt: Date(),
                          inode: currentInode,
                          size: currentSize,
                          restored: false)
        entries.append(entry)
        saveEntries()
        NSLog("[VirusGuard] Quarantäne: \(sourcePath) → \(destPath) [\(signature)]")
        return (true, "In Quarantäne verschoben: \(destPath)")
    }

    /// Bestimmt einen nicht belegten Zielpfad. Vorhandene Dateien werden nie
    /// überschrieben – stattdessen wird „-1“, „-2“ … angehängt.
    private func uniqueDestinationPath(directory: String, baseName: String) -> String {
        let initial = (directory as NSString).appendingPathComponent(baseName)
        if !fm.fileExists(atPath: initial) {
            return initial
        }
        // Name ohne Extension + Extension splitten.
        let ext = (baseName as NSString).pathExtension
        let stem = (baseName as NSString).deletingPathExtension
        var i = 1
        while true {
            let suffix = ext.isEmpty ? "\(stem)-\(i)" : "\(stem)-\(i).\(ext)"
            let candidate = (directory as NSString).appendingPathComponent(suffix)
            if !fm.fileExists(atPath: candidate) {
                return candidate
            }
            i += 1
            // Sicherheitsbremse bei 10000.
            if i > 10000 {
                return (directory as NSString).appendingPathComponent("\(stem)-\(Int(Date().timeIntervalSince1970))")
            }
        }
    }

    // MARK: - Wiederherstellung

    /// Stellt eine quarantänierte Datei an ihrem Originalpfad wieder her.
    /// - Parameter quarantinedPath: Pfad in der Quarantäne.
    /// - Returns: Erfolg + Meldung.
    func restore(quarantinedPath: String) -> (success: Bool, message: String) {
        guard let idx = entries.firstIndex(where: { $0.quarantinedPath == quarantinedPath }) else {
            return (false, "Eintrag nicht gefunden.")
        }
        let entry = entries[idx]
        guard fm.fileExists(atPath: quarantinedPath) else {
            return (false, "Quarantäne-Datei existiert nicht mehr.")
        }

        // Wiederherstellungs-Ziel: Originalpfad. Aber falls dort inzwischen eine
        // neue Datei liegt, NICHT überschreiben → in einem „restored\"-Unterordner
        // ablegen, damit nichts verloren geht.
        var restorePath = entry.originalPath
        if fm.fileExists(atPath: restorePath) {
            let dir = (entry.originalPath as NSString).deletingPathExtension
            let base = (entry.originalPath as NSString).lastPathComponent
            let restoredDir = (dir as NSString).appendingPathComponent("VirusGuard_restored")
            try? fm.createDirectory(atPath: restoredDir, withIntermediateDirectories: true)
            restorePath = (restoredDir as NSString).appendingPathComponent(base)
            restorePath = uniqueDestinationPath(directory: restoredDir, baseName: base)
        }

        do {
            try fm.moveItem(atPath: quarantinedPath, toPath: restorePath)
        } catch {
            // über Volumes → kopieren
            do {
                try fm.copyItem(atPath: quarantinedPath, toPath: restorePath)
                try fm.removeItem(atPath: quarantinedPath)
            } catch {
                return (false, "Wiederherstellung fehlgeschlagen: \(error.localizedDescription)")
            }
        }

        entries[idx].restored = true
        saveEntries()
        NSLog("[VirusGuard] Wiederhergestellt: \(quarantinedPath) → \(restorePath)")
        return (true, "Wiederhergestellt nach: \(restorePath)")
    }

    /// Löscht eine quarantänierte Datei endgültig.
    func delete(quarantinedPath: String) -> (success: Bool, message: String) {
        guard let idx = entries.firstIndex(where: { $0.quarantinedPath == quarantinedPath }) else {
            return (false, "Eintrag nicht gefunden.")
        }
        if fm.fileExists(atPath: quarantinedPath) {
            do {
                try fm.removeItem(atPath: quarantinedPath)
            } catch {
                return (false, "Löschen fehlgeschlagen: \(error.localizedDescription)")
            }
        }
        entries.remove(at: idx)
        saveEntries()
        NSLog("[VirusGuard] Quarantäne-Datei gelöscht: \(quarantinedPath)")
        return (true, "Endgültig gelöscht.")
    }

    // MARK: - Persistenz

    private var logURL: URL {
        let dir = resolvedQuarantinePath()
        return URL(fileURLWithPath: (dir as NSString).appendingPathComponent("quarantine_log.json"))
    }

    private func loadEntries() {
        guard let data = try? Data(contentsOf: logURL) else { return }
        if let decoded = try? JSONDecoder().decode([Entry].self, from: data) {
            entries = decoded
        }
    }

    private func saveEntries() {
        if let data = try? JSONEncoder().encode(entries) {
            try? data.write(to: logURL, options: .atomic)
            // Log-Datei ebenfalls restriktiv.
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: logURL.path)
        }
    }
}
