#!/bin/sh
# Generates the code-signing fixtures for the PE/JAR/APK tests: a self-signed certificate of a
# fictional developer and a PKCS#7 SignedData blob over a short text. Keys are new on every
# run, so the output is not byte-reproducible; the committed files are the reference.
set -e
cd "$(dirname "$0")"
tmp=$(mktemp -d)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
  -subj "/CN=Jane Developer/O=Example Software Ltd/C=GB" \
  -keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null
openssl x509 -in "$tmp/cert.pem" -outform DER -out codesign.der
printf 'signed content' > "$tmp/data"
openssl cms -sign -binary -nodetach -md sha256 -in "$tmp/data" -signer "$tmp/cert.pem" \
  -inkey "$tmp/key.pem" -outform DER -out codesign.p7
rm -rf "$tmp"
