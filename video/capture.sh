#!/usr/bin/env bash
# Capture the real terminal demo to /root/graphhacks-agent/video/take.mp4
# Fixed vs the first attempt: NO xterm -hold (that hung the wrapper's wait),
# and the encoder is finalized by a hard timeout on the whole run.
set -u
FF=/root/.hermes/tools/ffmpeg-9.0.1-linux-x64/bin/ffmpeg
OUT=/root/graphhacks-agent/video/take.mp4
rm -f "$OUT"

# 1. X display
Xvfb :99 -screen 0 1600x900x24 -ac >/dev/null 2>&1 &
XPID=$!
sleep 2

# 2. terminal running the paced demo (no -hold; exits when the script ends)
DISPLAY=:99 xterm -display :99 -geometry 1600x900+0+0 \
  -fa 'DejaVu Sans Mono' -fs 14 \
  -bg '#0c0c0c' -fg '#d8d8d8' -cr '#5aff8a' -title REFUSAL-AGENT \
  -e bash /root/graphhacks-agent/video/demo_script.sh &
XPID_X=$!
sleep 4

# 3. grabber at 30fps, clean CFR (no dup-frame stretch)
DISPLAY=:99 $FF -y -loglevel error -f x11grab -video_size 1600x900 \
  -framerate 30 -i :99.0 -c:v libx264 -preset veryfast -crf 18 \
  -pix_fmt yuv420p -t 90 "$OUT" &
FPID=$!

# 4. hard-stop the whole capture at 120s regardless
( sleep 90; kill -INT $FPID 2>/dev/null ) &
KILLER=$!
wait $FPID 2>/dev/null
kill $KILLER 2>/dev/null

# 5. cleanup
kill $XPID 2>/dev/null
kill $XPID_X 2>/dev/null
sleep 1

echo "=== take ==="
$FF -i "$OUT" 2>&1 | grep -E 'Duration|Stream'
