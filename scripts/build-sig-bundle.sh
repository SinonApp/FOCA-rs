#!/usr/bin/env bash
# Builds and signs the signature bundles for the update feeds from crates/foca-analysis/signatures.
# The signing key is not in the repository: pass the path to the 32-byte Ed25519 seed (64 hex chars).
# See docs/dev/signature-bundles.md.
#
#   scripts/build-sig-bundle.sh <seed file> <output bundle> [--schema v3|v2|both] [--version V] [--released YYYY-MM-DD]
#
# --schema v3 (default) writes the bundle for the `signatures-v3` feed (every table);
# --schema v2 writes the compatibility bundle for the `signatures` feed read by 2.0.0-beta.3
# (only the tables beta.3 knows); --schema both writes <output> (v3) and <output dir>/signatures.bundle (v2).
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 <seed file> <output bundle> [--schema v3|v2|both] [--version V] [--released YYYY-MM-DD]" >&2
  exit 2
fi
key=$1
out=$2
shift 2
if [ ! -f "$key" ]; then
  echo "$0: seed file $key not found" >&2
  exit 2
fi
schema=v3
rest=()
while [ $# -gt 0 ]; do
  if [ "$1" = "--schema" ]; then
    schema=${2:?--schema needs a value}
    shift 2
  else
    rest+=("$1")
    shift
  fi
done
cd "$(dirname "$0")/.."
mkdir -p "$(dirname "$out")"
build() {
  cargo run -q -p foca-engine --release --example sig_bundle -- build --key "$key" --out "$2" --schema "$1" ${rest[@]+"${rest[@]}"}
  cargo run -q -p foca-engine --release --example sig_bundle -- verify "$2"
}
case $schema in
  v3 | v2) build "$schema" "$out" ;;
  both)
    build v3 "$out"
    build v2 "$(dirname "$out")/signatures.bundle"
    ;;
  *)
    echo "$0: --schema must be v3, v2 or both" >&2
    exit 2
    ;;
esac
