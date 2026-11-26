#!/bin/bash
# Runs qa/docs-shots.mjs (README/docs screenshots and banner) with one Chromium at a time on the machine (flock).
# Machine-specific paths (where Playwright lives) go to qa/local.env (not in git); see qa/local.env.example.
QA="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$QA/local.env" ] && . "$QA/local.env"
if [ -n "${PW_DIR:-}" ]; then
  export PLAYWRIGHT_BROWSERS_PATH="$PW_DIR/browsers"
  export PW_CORE="${PW_CORE:-$PW_DIR/node_modules/playwright-core/index.js}"
fi
exec flock -w 900 /tmp/foca-pw.lock timeout 600 node "$QA/docs-shots.mjs" "$@"
