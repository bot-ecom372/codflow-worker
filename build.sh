#!/usr/bin/env bash
set -e

pip install -r requirements.txt

# Install Chromium for Playwright
# Try with system deps first (needs apt), fallback to browser-only
playwright install --with-deps chromium 2>/dev/null || playwright install chromium
