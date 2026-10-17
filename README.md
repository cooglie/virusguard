# VirusGuard 🛡️

Menüleisten-App für macOS, die regelmäßig und in **zufälligen Intervallen**
das System auf Malware scannt und bei Fund einen **nativen Dialog** zeigt, der
fragt, ob die Datei in Quarantäne verschoben werden soll.

Engine: **ClamAV** (aktiver Signature-Scan) **+ XProtect-Update** im Hintergrund.

---

## ⚡ All-in-One: Bauen & Starten

Ein einziger Befehl installiert ClamAV, aktualisiert die Signaturen, baut die
App und startet sie:

```bash
git clone https://github.com/cooglie/virusguard.git && \
cd virusguard && \
brew install clamav && \
freshclam && \
./build.sh && \
open build/VirusGuard.app
```

In der Menüleiste erscheint das 🛡️-Symbol — fertig.

> **Kein Homebrew?** Dann ClamAV manuell installieren
> ([clamav.net/downloads](https://www.clamav.net/downloads)) und
> `./build.sh && open build/VirusGuard.app` ausführen.

---

## Voraussetzungen

| Was | Womit |
|-----|------|
| macOS | 10.15 Catalina oder neuer |
| CPU  | Intel (x86_64) & Apple Silicon (arm64) – Universal-Binary |
| ClamAV | `brew install clamav` |
| Build-Tools | nur `swiftc` + `codesign` (Xcode Command Line Tools) |

### ClamAV einrichten (einmalig)

```bash
brew install clamav

# Signaturen aktualisieren
freshclam

# Optional: frische DB täglich via launchd (empfohlen)
brew services start clamav
```

Die `clamscan`-Binary liegt danach typischerweise unter
`/usr/local/bin/clamscan` (Intel-Homebrew) bzw.
`/opt/homebrew/bin/clamscan` (Apple Silicon) – der Pfad wird in der Config
konfiguriert (siehe unten).

---

## Bauen

```bash
cd virusguard
./build.sh
```

Ergebnis: `build/VirusGuard.app` (selbst-signiert/ad-hoc). Beim ersten Start
muss in *Systemeinstellungen → Datenschutz & Sicherheit* einmalig „Trotzdem
öffnen“ bestätigt werden.

Starten:

```bash
open build/VirusGuard.app
```

In der Menüleiste erscheint das 🛡️-Symbol.

---

## 🧪 Testvirus (EICAR)

Im Repo liegt eine harmlose Testdatei zum Prüfen, ob der Scan & die Quarantäne
funktionieren: [`test/eicar_test.txt`](test/eicar_test.txt). Das ist der
offizielle **EICAR-Standard-Antivirus-Test-String** — keine echte Malware, wird
aber von jedem Virenscanner (auch ClamAV) als „Eicar-Test-Signatur“ erkannt.

**Testablauf:**

```bash
# 1. App starten (s.o.)
# 2. Testdatei in einen gescannten Ordner kopieren (Desktop/Downloads werden per Default gescannt)
cp test/eicar_test.txt ~/Desktop/

# 3. Sofort scannen: 🛡️-Menü → "Jetzt scannen"
#    (oder auf den nächsten Timer-Scan warten)
```

Erwartet: VirusGuard meldet „1 Bedrohung erkannt“, zeigt den Dialog, und nach
„In Quarantäne verschieben“ liegt die Datei unter `~/Desktop/Quarantine/`.

---

## Konfiguration

Beim ersten Start wird eine Standard-Config erzeugt unter:

```
~/Library/Application Support/VirusGuard/config.json
```

Übers Menü (🛡️ → **Config öffnen**) editierbar. Felder:

| Feld | Bedeutung | Standard |
|------|-----------|----------|
| `minIntervalSeconds` | Unteres Limit des Zufallsintervalls | `600` (10 Min) |
| `maxIntervalSeconds` | Oberes Limit des Zufallsintervalls | `3600` (60 Min) |
| `scanPaths` | Liste der zu scannenden Pfade (`~` erlaubt) | `~/Downloads`, `~/Desktop` |
| `clamScanPath` | Pfad zur `clamscan`-Binary | `/usr/local/bin/clamscan` |
| `clamDatabase` | Eigene DB (leer = ClamAV-Standard) | `""` |
| `quarantineFolder` | Ziel für verschobene Funde | `~/Desktop/Quarantine` |
| `triggerXProtectUpdate` | XProtect-Updates im Hintergrund anstoßen | `true` |
| `scanOnce` | Debug: einmal scannen & beenden | `false` |

**Beispiel** für 30 Sek – 2 Stunden:

```json
{
  "minIntervalSeconds": 30,
  "maxIntervalSeconds": 7200,
  "scanPaths": ["~/Downloads", "~/Desktop", "~/Documents"],
  "clamScanPath": "/usr/local/bin/clamscan",
  "clamDatabase": "",
  "quarantineFolder": "~/Desktop/Quarantine",
  "triggerXProtectUpdate": true,
  "scanOnce": false
}
```

Nach Änderung: App beenden (🛡️ → **VirusGuard beenden**) und neu starten.

---

## Bei Fund

Sobald ClamAV eine Datei als infiziert meldet, öffnet sich ein Dialog:

```
Mögliche Malware erkannt
Datei: /Users/.../Downloads/badfile.exe
Signatur: Win.Trojan.Generic-123

[ In Quarantäne verschieben ]  [ Ignorieren ]  [ Alle restlichen ignorieren ]
```

* **Quarantäne** → Datei wird nach `quarantineFolder` verschoben (aus dem
  Originalort entfernt).
* **Ignorieren** → nur diese Datei überspringen.
* **Alle restlichen ignorieren** → verbleibende Funde des Scans überspringen.

Das Menüleisten-Icon wechselt bei Fund auf ⚠️ und nach dem nächsten sauberen
Scan zurück auf 🛡️.

---

## Autostart nach Reboot (optional)

Über *Systemeinstellungen → Allgemein → Anmeldeobjekte* die
`VirusGuard.app` hinzufügen. Alternativ als LaunchAgent:

```bash
mkdir -p ~/Library/LaunchAgents
cat > ~/Library/LaunchAgents/local.virusguard.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>local.virusguard</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/open</string>
    <string>/PFAD/ZU/VirusGuard.app</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/local.virusguard.plist
```

---

## Architektur / Sicherheit

* Kein Dock-Icon, nur Menüleiste (`LSUIElement = true`).
* Timer läuft mit **nicht-wiederholendem Timer** + Neuplanung nach jedem Scan –
  so ist das Intervall jedes Mal neu zufällig in `[min, max]`.
* ClamAV läuft als separater Prozess (`clamscan`); VirusGuard wertet nur die
  `FOUND`-Zeilen aus.
* XProtect-Update via `softwareupdate --background` läuft asynchron im
  Hintergrund und blockiert den Scan nicht.
* Alles offline, außer ClamAV-eigenem DB-Update via `freshclam`.

---

## Disclaimer

VirusGuard ist ein Wrapper um ClamAV und Apples XProtect. Es ersetzt keinen
echten Echtzeit-Schutz, sondern bietet regelmäßige Stichproben-Scans.
Signatur-Qualität = ClamAV-Datenbank.
