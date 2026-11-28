#!/usr/bin/env bash
# Writes and verifies the signed checksum files of a release for the in-app updater.
# See docs/dev/build.md, "Release Process".
#
#   scripts/sign-release.sh sign   [dist dir]   # SHA256SUMS.txt + SHA256SUMS.txt.sig for dist/*.apk
#   scripts/sign-release.sh verify [dist dir]   # checks the APK sums and the signature
#
# The signature is Ed25519 over b"FOCA-rs release SHA256SUMS v1\n" followed by the exact bytes of
# SHA256SUMS.txt, stored as 128 lowercase hex characters and a newline. The key is the signature
# bundle key (the app embeds its public half); the domain prefix keeps the two uses apart.
# The 32-byte seed (64 hex characters) is read from $FOCA_SIG_SEED, by default
# /root/.secrets/foca_sig_seed.hex. It never leaves a private temporary directory.
# Needs OpenSSL 3 and coreutils.
set -euo pipefail

mode=${1:-}
dist=${2:-dist}
seed_file=${FOCA_SIG_SEED:-/root/.secrets/foca_sig_seed.hex}
repo=$(cd "$(dirname "$0")/.." && pwd)
domain='FOCA-rs release SHA256SUMS v1'

die() {
  echo "sign-release: $*" >&2
  exit 1
}

usage() {
  echo "usage: $0 sign|verify [dist dir]" >&2
  exit 2
}

[ -n "$mode" ] || usage
[ -d "$dist" ] || die "directory $dist not found"
command -v openssl >/dev/null || die "openssl is required"

hex_to_bin() {
  local hex=$1
  printf '%b' "$(printf '%s' "$hex" | sed 's/../\\x&/g')"
}

# The public key compiled into the app (OFFICIAL_ED25519_PUBKEY in sigbundle.rs).
embedded_pubkey() {
  sed -n '/^const OFFICIAL_ED25519_PUBKEY/,/^];/p' "$repo/crates/foca-engine/src/services/sigbundle.rs" |
    grep -o '0x[0-9a-f][0-9a-f]' | sed 's/0x//' | tr -d '\n'
}

work=$(mktemp -d)
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT

message() {
  { printf '%s\n' "$domain"; cat "$dist/SHA256SUMS.txt"; } >"$work/msg"
}

pub_der() {
  local pub
  pub=$(embedded_pubkey)
  [ ${#pub} -eq 64 ] || die "could not read the embedded public key"
  hex_to_bin "302a300506032b6570032100$pub" >"$work/pub.der"
}

case $mode in
  sign)
    [ -r "$seed_file" ] || die "seed file $seed_file is not readable (set FOCA_SIG_SEED)"
    seed=$(tr -d ' \n\r' <"$seed_file")
    [[ $seed =~ ^[0-9a-fA-F]{64}$ ]] || die "$seed_file must hold 64 hex characters"
    shopt -s nullglob
    apks=("$dist"/*.apk)
    [ ${#apks[@]} -gt 0 ] || die "no APK in $dist"
    (umask 077 && hex_to_bin "302e020100300506032b657004220420$seed" >"$work/key.der")
    unset seed
    # The key must be the one the app trusts, or every phone would refuse the update.
    got=$(openssl pkey -inform DER -in "$work/key.der" -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')
    [ "$got" = "$(embedded_pubkey)" ] || die "the seed does not match the public key built into the app"
    (cd "$dist" && sha256sum -- *.apk) >"$dist/SHA256SUMS.txt"
    message
    openssl pkeyutl -sign -rawin -inkey "$work/key.der" -keyform DER -in "$work/msg" -out "$work/sig.bin"
    printf '%s\n' "$(od -An -tx1 "$work/sig.bin" | tr -d ' \n')" >"$dist/SHA256SUMS.txt.sig"
    echo "wrote $dist/SHA256SUMS.txt (${#apks[@]} APK) and $dist/SHA256SUMS.txt.sig"
    "$0" verify "$dist"
    ;;
  verify)
    [ -f "$dist/SHA256SUMS.txt" ] || die "$dist/SHA256SUMS.txt not found"
    [ -f "$dist/SHA256SUMS.txt.sig" ] || die "$dist/SHA256SUMS.txt.sig not found"
    sig=$(tr -d ' \n\r' <"$dist/SHA256SUMS.txt.sig")
    [[ $sig =~ ^[0-9a-f]{128}$ ]] || die "SHA256SUMS.txt.sig must hold 128 lowercase hex characters"
    hex_to_bin "$sig" >"$work/sig.bin"
    pub_der
    message
    openssl pkeyutl -verify -pubin -inkey "$work/pub.der" -keyform DER -rawin \
      -in "$work/msg" -sigfile "$work/sig.bin" >/dev/null || die "signature check FAILED"
    echo "signature: OK (key $(embedded_pubkey | cut -c1-16)...)"
    # Sums of the APKs present in the directory (a release may hold only some of them locally).
    shopt -s nullglob
    present=0
    while read -r hash name; do
      name=${name#\*}
      if [ -f "$dist/$name" ]; then
        present=$((present + 1))
        [ "$(sha256sum -- "$dist/$name" | cut -d' ' -f1)" = "$hash" ] || die "$name: SHA-256 mismatch"
        echo "$name: OK"
      fi
    done <"$dist/SHA256SUMS.txt"
    echo "verified $present APK against SHA256SUMS.txt"
    ;;
  *) usage ;;
esac
