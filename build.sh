#!/usr/bin/env bash
set -e

pip install -r requirements.txt

# Install Chromium (headless shell) using the venv's playwright, deterministically.
# --with-deps needs root (harmless no-op on Render native); fall back to
# browser-only download so the binary is always present.
python -m playwright install --with-deps chromium || python -m playwright install chromium
