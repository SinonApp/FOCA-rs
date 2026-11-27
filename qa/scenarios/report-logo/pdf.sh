#!/bin/bash
# Prints the HTML report with a logo to PDF and checks the PDF carries the logo as an image object.
# Usage: bash qa/scenarios/report-logo/pdf.sh
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
[ -f qa/local.env ] && . qa/local.env
if [ -n "${PW_DIR:-}" ]; then
  export PLAYWRIGHT_BROWSERS_PATH="$PW_DIR/browsers"
  export PW_CORE="${PW_CORE:-$PW_DIR/node_modules/playwright-core/index.js}"
fi
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
FOCA_REPORT_LOGO_HTML="$OUT/logo.html" cargo test -q -p foca-report --test logo html_embeds >/dev/null
flock -w 600 /tmp/foca-pw.lock node qa/scenarios/report-logo/pdf.mjs "$OUT/logo.html"
