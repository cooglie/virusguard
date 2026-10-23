import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {

    private var statusController: StatusItemController!
    private var scanner: Scanner!   // Referenz halten für Quarantäne-Aktion
    private var quarantineManager: QuarantineManager!
    private var reportWindow = ReportWindow()

    func applicationDidFinishLaunching(_ notification: Notification) {
        let config = VirusGuardConfig.load()
        scanner = Scanner(config: config)
        quarantineManager = QuarantineManager(config: config)
        scanner.quarantineManager = quarantineManager
        statusController = StatusItemController(config: config)

        // Report-Fenster an diesen Delegate binden
        reportWindow.wireActions(scanner: scanner, quarantineManager: quarantineManager)
        statusController.onFindingsDetected = { [weak self] result in
            self?.presentReport(result)
        }
        statusController.onScanCompleted = { [weak self] result in
            // Nur bei sauberen Scans automatisch Report zeigen; Fehler/Funde
            // werden bereits über onFindingsDetected bzw. Fehler-Dialoge angezeigt.
            if result.status == .clean {
                self?.presentReport(result)
            }
        }

        statusController.start()
    }

    // MARK: - Report

    /// Zeigt das Report-Fenster mit der Auswertung des Scans.
    private func presentReport(_ result: ScanResult) {
        reportWindow.present(result: result)
    }

    private func showAlert(title: String, text: String) {
        let a = NSAlert()
        a.alertStyle = .informational
        a.messageText = title
        a.informativeText = text
        a.addButton(withTitle: "OK")
        a.runModal()
    }

    func applicationWillTerminate(_ notification: Notification) {
        statusController?.stop()
    }
}
