#!/usr/bin/env bash
# Builds and signs the signature bundle for the update feed from crates/foca-analysis/signatures.
# The signing key is not in the repository: pass the path to the 32-byte Ed25519 seed (64 hex chars).
# See docs/dev/signature-bundles.md.
#
#   scripts/build-sig-bundle.sh <seed file> <output bundle> [--version V] [--released YYYY-MM-DD]
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 <seed file> <output bundle> [--version V] [--released YYYY-MM-DD]" >&2
  exit 2
fi
key=$1
out=$2
shift 2
if [ ! -f "$key" ]; then
  echo "$0: seed file $key not found" >&2
  exit 2
fi
cd "$(dirname "$0")/.."
mkdir -p "$(dirname "$out")"
cargo run -q -p foca-engine --release --example sig_bundle -- build --key "$key" --out "$out" "$@"
cargo run -q -p foca-engine --release --example sig_bundle -- verify "$out"
