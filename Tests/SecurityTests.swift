import Foundation
import AppKit

/// Sicherheits-Tests für VirusGuard (eigenständiger Runner, ohne XCTest).
///
/// Prüft die zentralen Sicherheitsversprechen aus der Code-Review:
///  1. Ein fehlerhafter/abgebrochener Scan wird NIEMALS als „sauber" gemeldet.
///  2. Quarantäne lehnt Symlinks ab.
///  3. Quarantäne erkennt TOCTOU (Inode/Größe verändert) und verweigert.
///  4. Quarantäne überschreibt niemals eine vorhandene Datei.
///  5. Config.validate erkennt Überschneidung Quarantäne ↔ Scan-Pfad.
///  6. Config.validate korrigiert unplausible Intervalle.
///  7. Signaturen gelten nach 7 Tagen als veraltet.
///
/// Kompilieren/Ausführen:
///   swiftc -target arm64-apple-macos11 -framework AppKit -framework Foundation \
///     Tests/SecurityTests.swift VirusGuard/**/*.swift -o /tmp/vg_tests && /tmp/vg_tests

// MARK: - Minimal-Assertion-Helpers

private var failures: [String] = []
private var passed = 0
private var currentName = ""

private func _assert(_ cond: @autoclosure () -> Bool, _ msg: @autoclosure () -> String = "",
                    file: String = #file, line: Int = #line) {
    if cond() { passed += 1 }
    else { failures.append("\(currentName): \(msg()) [\(file):\(line)]") }
}

private func _expect(_ caseMatch: Bool, _ msg: @autoclosure () -> String = "",
                     file: String = #file, line: Int = #line) {
    if caseMatch { passed += 1 }
    else { failures.append("\(currentName): \(msg()) [\(file):\(line)]") }
}

private func runTest(_ name: String, _ body: () -> Void) {
    currentName = name
    body()
}

// MARK: - Tests

// 1) ScanResult.status
func testEngineErrorNeverClean() {
    let r = ScanResult(findings: [], rawOutput: "", stderrOutput: "",
                       exitCode: 0, aborted: false,
                       engineError: "DB fehlt", filesScanned: 0, durationSeconds: 0)
    _assert(r.status != .clean, "Engine-Fehler darf nicht als clean gelten")
    if case .engineError = r.status { _expect(true) } else { _expect(false, "Expected engineError") }
}

func testAbortedNeverClean() {
    let r = ScanResult(findings: [], rawOutput: "", stderrOutput: "",
                       exitCode: 0, aborted: true,
                       engineError: nil, filesScanned: 0, durationSeconds: 0)
    _assert(r.status != .clean, "Abbruch darf nicht als clean gelten")
    if case .scanError = r.status { _expect(true) } else { _expect(false, "Expected scanError") }
}

func testExitCode2IsScanError() {
    let r = ScanResult(findings: [], rawOutput: "", stderrOutput: "boom",
                       exitCode: 2, aborted: false,
                       engineError: nil, filesScanned: 0, durationSeconds: 0)
    _assert(r.status != .clean)
    if case .scanError = r.status { _expect(true) } else { _expect(false, "Expected scanError for exit 2") }
}

func testSignalExitNeverClean() {
    let r = ScanResult(findings: [], rawOutput: "", stderrOutput: "",
                       exitCode: 143, aborted: true,
                       engineError: nil, filesScanned: 0, durationSeconds: 0)
    _assert(r.status != .clean, "Signal-Termination darf nicht clean sein")
}

func testCleanOnlyWhenExitZeroNoFindingsNoError() {
    let r = ScanResult(findings: [], rawOutput: "", stderrOutput: "",
                       exitCode: 0, aborted: false,
                       engineError: nil, filesScanned: 42, durationSeconds: 1)
    _assert(r.status == .clean, "Sollte clean sein")
}

func testInfectedWhenFindings() {
    let r = ScanResult(findings: [("/tmp/eicar", "Eicar-Test")], rawOutput: "",
                       stderrOutput: "", exitCode: 1, aborted: false,
                       engineError: nil, filesScanned: 1, durationSeconds: 0)
    if case .infected = r.status { _expect(true) } else { _expect(false, "Expected infected") }
}

// 2-4) QuarantineManager
private func makeManager() -> (QuarantineManager, String, String) {
    let tmp = NSTemporaryDirectory() + "vgtest_\(UUID().uuidString)/"
    let qDir = tmp + "quarantine/"
    let srcDir = tmp + "src/"
    try? FileManager.default.createDirectory(atPath: qDir, withIntermediateDirectories: true)
    try? FileManager.default.createDirectory(atPath: srcDir, withIntermediateDirectories: true)
    var cfg = VirusGuardConfig.default
    cfg.quarantineFolder = qDir
    let mgr = QuarantineManager(config: cfg)
    return (mgr, qDir, srcDir)
}

func testQuarantineRejectsSymlink() {
    let (mgr, _, srcDir) = makeManager()
    let real = srcDir + "real.txt"
    let link = srcDir + "link.txt"
    try? "hello".write(toFile: real, atomically: true, encoding: .utf8)
    try? FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)
    let result = mgr.quarantine(sourcePath: link, signature: "Test")
    _assert(!result.success, "Symlink darf nicht quarantäniert werden")
    _assert(FileManager.default.fileExists(atPath: link), "Quelle muss erhalten bleiben")
}

func testQuarantineRejectsTOCTOU_InodeChanged() {
    let (mgr, _, srcDir) = makeManager()
    let f = srcDir + "target.txt"
    try? "original".write(toFile: f, atomically: true, encoding: .utf8)
    let attrs = try! FileManager.default.attributesOfItem(atPath: f)
    let inode = (attrs[.systemFileNumber] as! NSNumber).uint64Value
    let size = (attrs[.size] as! NSNumber).uint64Value
    try? FileManager.default.removeItem(atPath: f)
    try? "replaced".write(toFile: f, atomically: true, encoding: .utf8)
    let result = mgr.quarantine(sourcePath: f, signature: "Test",
                                scannedInode: inode, scannedSize: size)
    _assert(!result.success, "TOCTOU (Inode geändert) muss abgelehnt werden")
}

func testQuarantineRejectsTOCTOU_SizeChanged() {
    let (mgr, _, srcDir) = makeManager()
    let f = srcDir + "target.txt"
    try? "aa".write(toFile: f, atomically: true, encoding: .utf8)
    let attrs = try! FileManager.default.attributesOfItem(atPath: f)
    let inode = (attrs[.systemFileNumber] as! NSNumber).uint64Value
    let size = (attrs[.size] as! NSNumber).uint64Value
    try? "aaaaaa".write(toFile: f, atomically: true, encoding: .utf8)
    let result = mgr.quarantine(sourcePath: f, signature: "Test",
                                scannedInode: inode, scannedSize: size)
    _assert(!result.success, "TOCTOU (Größe geändert) muss abgelehnt werden")
}

func testQuarantineNeverOverwrites() {
    let (mgr, qDir, srcDir) = makeManager()
    let blocker = qDir + "file.txt"
    try? "blocker".write(toFile: blocker, atomically: true, encoding: .utf8)
    let f = srcDir + "file.txt"
    try? "malware".write(toFile: f, atomically: true, encoding: .utf8)
    let result = mgr.quarantine(sourcePath: f, signature: "Test")
    _assert(result.success, "Quarantäne sollte durch Umbenennung Erfolg haben")
    let content = try? String(contentsOfFile: blocker, encoding: .utf8)
    _assert(content == "blocker", "Vorhandene Datei darf nicht überschrieben werden")
    _assert(FileManager.default.fileExists(atPath: qDir + "file-1.txt"), "Umbenannte Kopie muss existieren")
}

func testQuarantinePreservesOriginalOnMissingSource() {
    let (mgr, _, srcDir) = makeManager()
    let f = srcDir + "keepme.txt"
    try? "data".write(toFile: f, atomically: true, encoding: .utf8)
    let attrs = try! FileManager.default.attributesOfItem(atPath: f)
    let inode = (attrs[.systemFileNumber] as! NSNumber).uint64Value
    let size = (attrs[.size] as! NSNumber).uint64Value
    let result = mgr.quarantine(sourcePath: srcDir + "doesnotexist.txt",
                                signature: "X", scannedInode: inode, scannedSize: size)
    _assert(!result.success, "Nichtexistente Quelle muss fehlschlagen")
    _assert(FileManager.default.fileExists(atPath: f), "Original bleibt unangetastet")
}

// 5-6) Config.validate
func testConfigDetectsQuarantineInsideScanPath() {
    var cfg = VirusGuardConfig.default
    cfg.scanPaths = ["/Users/test/Downloads"]
    cfg.quarantineFolder = "/Users/test/Downloads/quarantine"
    let warnings = cfg.validate()
    _assert(warnings.contains { $0.contains("Quarantäne-Ordner liegt im Scan-Pfad") },
            "Überschneidung Q-in-Scan muss erkannt werden")
}

func testConfigDetectsScanPathInsideQuarantine() {
    var cfg = VirusGuardConfig.default
    cfg.quarantineFolder = "/Users/test/Quarantine"
    cfg.scanPaths = ["/Users/test/Quarantine/subfolder"]
    let warnings = cfg.validate()
    _assert(warnings.contains { $0.contains("Scan-Pfad liegt im Quarantäne-Ordner") },
            "Überschneidung Scan-in-Q muss erkannt werden")
}

func testConfigCorrectsIntervals() {
    var cfg = VirusGuardConfig.default
    cfg.minIntervalSeconds = 0
    cfg.maxIntervalSeconds = -5
    let warnings = cfg.validate()
    _assert(cfg.minIntervalSeconds >= 1)
    _assert(cfg.maxIntervalSeconds >= cfg.minIntervalSeconds)
    _assert(!warnings.isEmpty)
}

func testConfigCapsMaxInterval() {
    var cfg = VirusGuardConfig.default
    cfg.minIntervalSeconds = 10
    cfg.maxIntervalSeconds = 1000000
    _ = cfg.validate()
    _assert(cfg.maxIntervalSeconds == 86400, "Max-Intervall muss auf 24h gedeckelt werden")
}

func testConfigEmptyScanPathsGetsDefault() {
    var cfg = VirusGuardConfig.default
    cfg.scanPaths = []
    _ = cfg.validate()
    _assert(!cfg.scanPaths.isEmpty, "Leere Scan-Pfade müssen Default erhalten")
}

// 7) Signatur-Alter
func testSignatureStaleThresholdIs7Days() {
    _assert(SignatureUpdateManager.staleInterval == 7 * 24 * 3600,
            "Signatur-Veraltet-Schwelle muss 7 Tage sein")
}

// MARK: - Runner

@main
struct TestRunner {
    static func main() {
        let tests: [(String, () -> Void)] = [
            ("testEngineErrorNeverClean", testEngineErrorNeverClean),
            ("testAbortedNeverClean", testAbortedNeverClean),
            ("testExitCode2IsScanError", testExitCode2IsScanError),
            ("testSignalExitNeverClean", testSignalExitNeverClean),
            ("testCleanOnlyWhenExitZeroNoFindingsNoError", testCleanOnlyWhenExitZeroNoFindingsNoError),
            ("testInfectedWhenFindings", testInfectedWhenFindings),
            ("testQuarantineRejectsSymlink", testQuarantineRejectsSymlink),
            ("testQuarantineRejectsTOCTOU_InodeChanged", testQuarantineRejectsTOCTOU_InodeChanged),
            ("testQuarantineRejectsTOCTOU_SizeChanged", testQuarantineRejectsTOCTOU_SizeChanged),
            ("testQuarantineNeverOverwrites", testQuarantineNeverOverwrites),
            ("testQuarantinePreservesOriginalOnMissingSource", testQuarantinePreservesOriginalOnMissingSource),
            ("testConfigDetectsQuarantineInsideScanPath", testConfigDetectsQuarantineInsideScanPath),
            ("testConfigDetectsScanPathInsideQuarantine", testConfigDetectsScanPathInsideQuarantine),
            ("testConfigCorrectsIntervals", testConfigCorrectsIntervals),
            ("testConfigCapsMaxInterval", testConfigCapsMaxInterval),
            ("testConfigEmptyScanPathsGetsDefault", testConfigEmptyScanPathsGetsDefault),
            ("testSignatureStaleThresholdIs7Days", testSignatureStaleThresholdIs7Days),
        ]
        for (name, body) in tests { runTest(name, body) }
        print("\n=== VirusGuard Sicherheits-Tests ===")
        print("Bestanden: \(passed)/\(tests.count)")
        if failures.isEmpty {
            print("✅ Alle Tests bestanden.")
            exit(0)
        } else {
            print("❌ \(failures.count) Test(s) fehlgeschlagen:")
            for f in failures { print("  • \(f)") }
            exit(1)
        }
    }
}
