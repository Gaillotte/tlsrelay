#!/usr/bin/env bash
# Produces the demonstration video (MP4, 1280x720, no sound, English captions):
#   1. records a real run of tools/demo.sh with its timing (script -T);
#   2. builds and runs tlsrelay-admin-tour: one image per editor screen, using
#      the files of that run (no display needed);
#   3. replays the run in a browser terminal (xterm.js) with chapter cards and
#      captions, adds the editor screens, records the page (Playwright);
#   4. encodes the MP4 (ffmpeg, H.264).
# Requirements: a build with the editor (TLSRELAY_BUILD_ADMIN=ON), node with the
# playwright package and its Chromium, ffmpeg, npm access for xterm.js, util-linux script.
# Usage : tools/video/make-video.sh <build directory> [output.mp4]
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
build=$(cd "${1:?usage: make-video.sh <build directory> [output.mp4]}" && pwd)
output=$(realpath -m "${2:-$root/tlsrelay-demo.mp4}")
for tool in ffmpeg node npm script; do command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 2; }; done

work=$(mktemp -d)
demo=/tmp/tlsrelay-demo   # short path: it appears on screen
trap 'rm -rf "$work"' EXIT
rm -rf "$demo"

echo "== 1/4 recording tools/demo.sh"
if ! script -q -e -T "$work/timing.log" \
  -c "stty cols 110 rows 30; cd '$root' && DEMO_DIR='$demo' tools/demo.sh '$build'" "$work/typescript.txt" >/dev/null; then
  # The video only shows a run where every check passed.
  cp "$work/typescript.txt" "$demo/typescript.txt"
  echo "the demonstration failed (recording kept in $demo/typescript.txt):" >&2
  grep -a -E "✘|Result" "$work/typescript.txt" | sed 's/\x1b\[[0-9;]*m//g' >&2
  exit 1
fi

echo "== 2/4 editor screens"
cmake --build "$build" --target tlsrelay-admin-tour >/dev/null
# (the offscreen platform warns that it cannot resize windows to their hints: harmless)
XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-$demo/.runtime} "$build/src/admin/tlsrelay-admin-tour" "$demo" "$work/shots" \
  2> >(grep -v propagateSizeHints >&2) >/dev/null

echo "== 3/4 rendering"
(cd "$work" && npm init -y >/dev/null && npm install --silent --no-audit --no-fund @xterm/xterm@5.5.0)
NODE_PATH=${NODE_PATH:-$(npm root -g)} node "$root/tools/video/render.js" \
  "$work/typescript.txt" "$work/timing.log" "$work/shots" "$work/node_modules/@xterm/xterm" "$work/raw.webm"

echo "== 4/4 encoding"
# The first second is the page loading; the result plays on any device.
ffmpeg -loglevel error -y -ss 1 -i "$work/raw.webm" -c:v libx264 -preset slow -crf 22 -pix_fmt yuv420p \
  -movflags +faststart "$output"
echo "video: $output ($(du -h "$output" | cut -f1), $(ffprobe -v error -show_entries format=duration -of csv=p=0 "$output" | cut -d. -f1) s)"
