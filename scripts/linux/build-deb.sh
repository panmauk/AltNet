#!/usr/bin/env bash
# Build a .deb for AltNet Studio (Ubuntu/Debian).
set -e
export PATH="$PATH:/usr/local/go/bin:/root/go/bin"
SRC=/mnt/c/Users/rober/Documents/Internet
DST=~/altnet
VER=1.0.0
PKG=altnet-studio
ROOT=/tmp/${PKG}_${VER}_amd64

# sync + build fresh binaries
cd "$SRC"
tar --exclude=node_modules --exclude='*.exe' --exclude=.git --exclude=build \
    --exclude=data --exclude='*.zip' -cf - . 2>/dev/null | ( cd "$DST" && tar xf - )
cd "$DST" && go build -o /tmp/altnet-daemon ./cli
cd "$DST/app/desktop" && wails build -tags webkit2_41 >/dev/null 2>&1
echo "binaries built"

# package tree
rm -rf "$ROOT"
mkdir -p "$ROOT/DEBIAN" \
         "$ROOT/opt/altnet-studio" \
         "$ROOT/usr/bin" \
         "$ROOT/usr/share/applications" \
         "$ROOT/usr/share/icons/hicolor/256x256/apps"

cp "$DST/app/desktop/build/bin/AltNetStudio" "$ROOT/opt/altnet-studio/AltNetStudio"
cp /tmp/altnet-daemon "$ROOT/opt/altnet-studio/altnet"
cp "$SRC/app/desktop/build/appicon.png" "$ROOT/usr/share/icons/hicolor/256x256/apps/altnet-studio.png"
chmod 755 "$ROOT/opt/altnet-studio/AltNetStudio" "$ROOT/opt/altnet-studio/altnet"

# launcher: elevate to root (the app needs it) preserving the display
cat > "$ROOT/usr/bin/altnet-studio" <<'EOF'
#!/bin/sh
# AltNet Studio must run as root (binds :80, edits systemd-resolved,
# installs its CA). If we're not root, relaunch via pkexec, carrying the
# desktop session's display env so the window still appears.
APP=/opt/altnet-studio/AltNetStudio
if [ "$(id -u)" -ne 0 ]; then
    # Let the root process talk to this user's X server (XWayland/X11).
    xhost +si:localuser:root >/dev/null 2>&1 || true
    exec pkexec env \
        DISPLAY="$DISPLAY" \
        XAUTHORITY="$XAUTHORITY" \
        WAYLAND_DISPLAY="$WAYLAND_DISPLAY" \
        XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
        GDK_BACKEND=x11 \
        "$APP" "$@"
fi
exec "$APP" "$@"
EOF
chmod 755 "$ROOT/usr/bin/altnet-studio"

# menu entry
cat > "$ROOT/usr/share/applications/altnet-studio.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=AltNet Studio
GenericName=Peer-to-peer internet
Comment=Run an AltNet node and browse .alt sites
Exec=altnet-studio
Icon=altnet-studio
Terminal=false
Categories=Network;P2P;
Keywords=altnet;p2p;decentralized;alt;
EOF

# control + maintainer scripts
INSTALLED_KB=$(du -ks "$ROOT/opt" | cut -f1)
cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $VER
Section: net
Priority: optional
Architecture: amd64
Depends: libwebkit2gtk-4.1-0, libgtk-3-0
Recommends: pkexec | policykit-1, x11-xserver-utils, systemd-resolved, ca-certificates
Installed-Size: $INSTALLED_KB
Maintainer: PANMOX <panmauk@panmox.org>
Description: AltNet Studio - peer-to-peer alternative internet
 Run an AltNet node and browse .alt sites served peer-to-peer.
 .
 The app runs as root (the launcher elevates via pkexec) because it binds
 port 80 for .alt sites, configures systemd-resolved to resolve .alt
 names, and installs AltNet's local certificate authority.
EOF

cat > "$ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
update-desktop-database -q /usr/share/applications 2>/dev/null || true
gtk-update-icon-cache -q -t /usr/share/icons/hicolor 2>/dev/null || true
exit 0
EOF
chmod 755 "$ROOT/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "$ROOT" >/dev/null
DEB="${ROOT}.deb"
cp "$DEB" "$SRC/"
echo "=== built ==="
ls -la "$DEB"
echo "=== lint ==="
dpkg-deb -I "$DEB" | sed -n '1,20p'
echo "=== contents ==="
dpkg-deb -c "$DEB"
