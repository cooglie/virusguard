#!/bin/bash
# Buildet VirusGuard als .app-Bundle (Universal: Intel x86_64 + Apple Silicon arm64, macOS 10.15+).
# Kein Xcode-Projekt nötig – nutzt direkt swiftc.
set -euo pipefail

cd "$(dirname "$0")"

APP_NAME="VirusGuard"
SRC_DIR="VirusGuard"
BUILD_DIR="build"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"

SWIFT_FILES=()
while IFS= read -r f; do SWIFT_FILES+=("$f"); done < <(find "$SRC_DIR" -name '*.swift' | sort)
echo "📦 Quellen: ${SWIFT_FILES[*]}"

echo "🧹 Bereinige altes Build …"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "🔨 Kompiliere (Universal x86_64 + arm64, deployment target 10.15) …"
swiftc \
    -target x86_64-apple-macos10.15 \
    -O \
    -framework AppKit -framework Foundation \
    "${SWIFT_FILES[@]}" \
    -o "$BUILD_DIR/$APP_NAME.x86_64"
swiftc \
    -target arm64-apple-macos11 \
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
