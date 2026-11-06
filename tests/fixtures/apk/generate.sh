#!/bin/sh
# Regenerates the APK v1 (JAR) signature fixtures for apk_android::signer.
# CERT.SF is a minimal signature file; CERT.RSA is the detached PKCS#7 that
# jarsigner/apksigner write over it: SHA-256 with RSA, no signed attributes,
# the content left out. The key is throwaway and not kept.
set -eu
cd "$(dirname "$0")"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

printf 'Signature-Version: 1.0\r\nCreated-By: filefacts fixture\r\nSHA-256-Digest-Manifest: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\r\n\r\n' > CERT.SF
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/key.pem" 2>/dev/null
openssl req -x509 -new -key "$T/key.pem" -subj "/CN=filefacts apk fixture" -days 3650 -sha256 -out "$T/cert.pem" 2>/dev/null
openssl cms -sign -binary -noattr -md sha256 -outform DER \
  -in CERT.SF -signer "$T/cert.pem" -inkey "$T/key.pem" -out CERT.RSA

# BOUND.*: a complete v1 signature over a two-member APK. BOUND.MF is the
# JAR manifest, with a SHA-256 digest of each member; BOUND.SF digests the
# whole manifest and each of its sections; BOUND.RSA signs BOUND.SF. The
# tests place them at META-INF/MANIFEST.MF, META-INF/BOUND.SF and
# META-INF/BOUND.RSA beside these members:
#   AndroidManifest.xml  "not axml"
#   classes.dex          "dex\n035\0"
b64sha() { openssl dgst -sha256 -binary | base64; }
DEX=$(printf 'dex\n035\000' | b64sha)
AXML=$(printf 'not axml' | b64sha)
printf 'Manifest-Version: 1.0\r\nCreated-By: filefacts fixture\r\n\r\n' > BOUND.MF
printf 'Name: AndroidManifest.xml\r\nSHA-256-Digest: %s\r\n\r\n' "$AXML" >> BOUND.MF
printf 'Name: classes.dex\r\nSHA-256-Digest: %s\r\n\r\n' "$DEX" >> BOUND.MF
{
  printf 'Signature-Version: 1.0\r\nCreated-By: filefacts fixture\r\n'
  printf 'SHA-256-Digest-Manifest: %s\r\n\r\n' "$(b64sha < BOUND.MF)"
  printf 'Name: AndroidManifest.xml\r\nSHA-256-Digest: %s\r\n\r\n' \
    "$(printf 'Name: AndroidManifest.xml\r\nSHA-256-Digest: %s\r\n\r\n' "$AXML" | b64sha)"
  printf 'Name: classes.dex\r\nSHA-256-Digest: %s\r\n\r\n' \
    "$(printf 'Name: classes.dex\r\nSHA-256-Digest: %s\r\n\r\n' "$DEX" | b64sha)"
} > BOUND.SF
openssl cms -sign -binary -noattr -md sha256 -outform DER \
  -in BOUND.SF -signer "$T/cert.pem" -inkey "$T/key.pem" -out BOUND.RSA
