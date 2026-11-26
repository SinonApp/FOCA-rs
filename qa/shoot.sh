#!/bin/bash
# Wrapper that allows only one Chromium at a time on the machine (flock) to avoid running out of memory.
# Machine-specific paths (where Playwright lives) go to qa/local.env (not in git); see qa/local.env.example.
QA="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$QA/local.env" ] && . "$QA/local.env"
if [ -n "${PW_DIR:-}" ]; then
  export PLAYWRIGHT_BROWSERS_PATH="$PW_DIR/browsers"
  export PW_CORE="${PW_CORE:-$PW_DIR/node_modules/playwright-core/index.js}"
fi
exec flock -w 600 /tmp/foca-pw.lock timeout 180 node "$QA/shoot.mjs" "$@"
