#!/usr/bin/env bash
# Build AltNet daemon + Studio GUI for Linux inside WSL.
set -e
export PATH="$PATH:/usr/local/go/bin:/root/go/bin"
SRC=/mnt/c/Users/rober/Documents/Internet
DST=~/altnet

echo "=== syncing source to WSL native FS ==="
mkdir -p "$DST"
cd "$SRC"
tar --exclude=node_modules --exclude='*.exe' --exclude=.git --exclude=build \
    --exclude=data --exclude='*.zip' -cf - . 2>/dev/null | ( cd "$DST" && tar xf - )

cd "$DST"
echo "=== building daemon (cli) ==="
go build -o /tmp/altnet-daemon ./cli
echo "DAEMON OK: $(stat -c %s /tmp/altnet-daemon) bytes"

echo "=== module check: does app/desktop have its own go.mod? ==="
ls -la app/desktop/go.mod 2>/dev/null && echo "(separate module)" || echo "(part of root module)"

echo "=== building Studio GUI (wails, webkit2_41) ==="
cd "$DST/app/desktop"
wails build -tags webkit2_41 2>&1 | tail -20
echo "=== result ==="
ls -la build/bin/ 2>/dev/null || echo "no build/bin"
