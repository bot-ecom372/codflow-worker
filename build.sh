#!/usr/bin/env bash
set -e

pip install -r requirements.txt

# Install Chromium (headless shell) using the venv's playwright, deterministically.
# --with-deps needs root (harmless no-op on Render native); fall back to
# browser-only download so the binary is always present.
python -m playwright install --with-deps chromium || python -m playwright install chromium

# Pre-download Whisper small int8 into the slug so the first vocal after a
# deploy doesn't pay the ~460MB model download.
python - <<'EOF'
from faster_whisper import WhisperModel
WhisperModel("small", device="cpu", compute_type="int8", download_root="./whisper-models")
print("whisper small int8 cached")
EOF
