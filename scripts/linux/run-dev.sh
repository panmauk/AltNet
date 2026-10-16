#!/usr/bin/env bash
# Launch the Linux Studio GUI via WSLg with WebKit software-rendering
# workarounds (WSLg has no real GPU; WebKit's DMABUF/compositing path
# draws a blank window without these).
export PATH="$PATH:/usr/local/go/bin:/root/go/bin"
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export LIBGL_ALWAYS_SOFTWARE=1
export GDK_BACKEND=x11

BIN=~/altnet/app/desktop/build/bin
pkill -f AltNetStudio 2>/dev/null
sleep 1
cp /tmp/altnet-daemon "$BIN/altnet"
chmod +x "$BIN/altnet" "$BIN/AltNetStudio"
cd "$BIN"
nohup ./AltNetStudio > /tmp/studio.log 2>&1 &
PID=$!
echo "launched PID=$PID with WebKit software rendering"
sleep 9
if kill -0 "$PID" 2>/dev/null; then echo "RUNNING"; else echo "EXITED"; fi
echo "=== log ==="
cat /tmp/studio.log
