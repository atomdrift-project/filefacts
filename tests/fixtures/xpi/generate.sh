#!/bin/sh
# Regenerates the XPI (Firefox add-on) PKCS #7 signature fixtures for
# jar_signature under Scheme::Mozilla, laid out as AMO signs an add-on:
# manifest.mf digests each member under SHA-1 and SHA-256; mozilla.sf
# digests only the whole manifest; mozilla.rsa is the detached PKCS#7 over
# mozilla.sf. The tests place them at META-INF/manifest.mf,
# META-INF/mozilla.sf and META-INF/mozilla.rsa beside these members:
#   manifest.json  '{"manifest_version":2,"name":"fixture","version":"1.0"}'
#   background.js  'console.log("fixture");'
# The key is throwaway and not kept.
set -eu
cd "$(dirname "$0")"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

MANIFEST_JSON='{"manifest_version":2,"name":"fixture","version":"1.0"}'
BACKGROUND_JS='console.log("fixture");'
b64() { openssl dgst "-$1" -binary | base64; }
section() {
  printf 'Name: %s\nDigest-Algorithms: SHA1 SHA256\nSHA1-Digest: %s\nSHA256-Digest: %s\n\n' \
    "$1" "$(printf '%s' "$2" | b64 sha1)" "$(printf '%s' "$2" | b64 sha256)"
}
{
  printf 'Manifest-Version: 1.0\n\n'
  section manifest.json "$MANIFEST_JSON"
  section background.js "$BACKGROUND_JS"
} > manifest.mf
printf 'Signature-Version: 1.0\nSHA1-Digest-Manifest: %s\nSHA256-Digest-Manifest: %s\n\n' \
  "$(b64 sha1 < manifest.mf)" "$(b64 sha256 < manifest.mf)" > mozilla.sf
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/key.pem" 2>/dev/null
openssl req -x509 -new -key "$T/key.pem" -subj "/CN=filefacts xpi fixture/O=Filefacts Fixtures" \
  -days 3650 -sha256 -out "$T/cert.pem" 2>/dev/null
openssl cms -sign -binary -md sha256 -outform DER \
  -in mozilla.sf -signer "$T/cert.pem" -inkey "$T/key.pem" -out mozilla.rsa
