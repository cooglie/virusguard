#!/bin/bash
# Buildet VirusGuard als .app-Bundle (Universal: Intel x86_64 + Apple Silicon arm64, macOS 11+).
# Kein Xcode-Projekt nötig – nutzt direkt swiftc.
#
# Schritte:
#  1. Sicherheits-Tests kompilieren + ausführen (schlagen fehl → Build bricht ab).
#  2. Universal-Binary (lipo) bauen.
#  3. .app-Bundle schnüren + ad-hoc signieren.
set -euo pipefail

cd "$(dirname "$0")"

APP_NAME="VirusGuard"
SRC_DIR="VirusGuard"
BUILD_DIR="build"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
# Deployment-Target: konsistent macOS 11 (arm64 benötigt ≥ 11).
DEPLOY_TARGET="macos11"
HOST_ARCH="$(uname -m)"

SWIFT_FILES=()
while IFS= read -r f; do SWIFT_FILES+=("$f"); done < <(find "$SRC_DIR" -name '*.swift' | sort)
echo "📦 Quellen: ${SWIFT_FILES[*]}"

# ─── 1. Sicherheits-Tests ─────────────────────────────────────────────────
# Tests müssen grün sein, bevor das Binary gebaut wird. Sie prüfen die
# zentralen Sicherheitsversprechen (ScanResult, TOCTOU, Symlink, Config).
if [[ -f Tests/SecurityTests.swift ]]; then
    mkdir -p "$BUILD_DIR"
    echo "🧪 Kompiliere Sicherheits-Tests …"
    TEST_SRC=()
    while IFS= read -r f; do
        case "$f" in */main.swift) continue;; esac   # main.swift hat Top-Level-Code
        TEST_SRC+=("$f")
    done < <(find "$SRC_DIR" -name '*.swift' | sort)
    swiftc -target "${HOST_ARCH}-apple-${DEPLOY_TARGET}" -parse-as-library \
        -framework Foundation -framework AppKit \
        Tests/SecurityTests.swift "${TEST_SRC[@]}" -o "$BUILD_DIR/.vg_tests" 2>&1
    echo "🏃 Führe Tests aus …"
    set +e
    "$BUILD_DIR/.vg_tests"
    TEST_EXIT=$?
    set -e
    rm -f "$BUILD_DIR/.vg_tests"
    if [[ $TEST_EXIT -ne 0 ]]; then
        echo "❌ Sicherheits-Tests fehlgeschlagen – Build abgebrochen."
        exit $TEST_EXIT
    fi
    echo "✅ Sicherheits-Tests bestanden."
fi

echo "🧹 Bereinige altes Build …"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "🔨 Kompiliere (Universal x86_64 + arm64, deployment target $DEPLOY_TARGET) …"
swiftc \
    -target x86_64-apple-$DEPLOY_TARGET \
    -O \
    -framework AppKit -framework Foundation \
    "${SWIFT_FILES[@]}" \
    -o "$BUILD_DIR/$APP_NAME.x86_64"
swiftc \
    -target arm64-apple-$DEPLOY_TARGET \
    -O \
    -framework AppKit -framework Foundation \
    "${SWIFT_FILES[@]}" \
    -o "$BUILD_DIR/$APP_NAME.arm64"
lipo -create -output "$BUILD_DIR/$APP_NAME" \
    "$BUILD_DIR/$APP_NAME.x86_64" \
    "$BUILD_DIR/$APP_NAME.arm64"

echo "📦 Erstelle .app-Bundle …"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"
cp "$BUILD_DIR/$APP_NAME" "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
cp "$SRC_DIR/Info.plist" "$APP_BUNDLE/Contents/Info.plist"
# App-Icon ins Bundle kopieren (falls vorhanden)
if [[ -f "$SRC_DIR/Resources/AppIcon.icns" ]]; then
    cp "$SRC_DIR/Resources/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
    echo "🎨 Icon eingebettet."
fi

echo "✍️  Codesign (self-sign, ad-hoc) …"
codesign --force --deep --sign - "$APP_BUNDLE"

echo "✅ Fertig: $APP_BUNDLE"
echo "   Starten: open \"$APP_BUNDLE\""
