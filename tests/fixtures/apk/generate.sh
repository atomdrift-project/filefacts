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
