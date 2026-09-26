#!/bin/sh
# Regenerates the certificate-bag fixtures for pe_authenticode::verified_chain.
# Each .p7b is a certs-only PKCS#7 SignedData (openssl crl2pkcs7), which is the
# shape of an Authenticode certificate bag without a SignerInfo. Keys are
# throwaway and not kept; rerunning produces new thumbprints, so the tests
# compare chains structurally (by subject), never by pinned thumbprint.
set -eu
cd "$(dirname "$0")"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

key() { # name algorithm
  case $2 in
    rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/$1.key" 2>/dev/null ;;
    p256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$T/$1.key" 2>/dev/null ;;
    p384) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$T/$1.key" 2>/dev/null ;;
  esac
}
root() { # name cn digest
  openssl req -x509 -new -key "$T/$1.key" -subj "/CN=$2" -days 3650 "-$3" -out "$T/$1.pem" 2>/dev/null
}
issue() { # name cn issuer-name digest
  openssl req -new -key "$T/$1.key" -subj "/CN=$2" -out "$T/$1.csr" 2>/dev/null
  printf 'basicConstraints=CA:TRUE\n' > "$T/ext"
  openssl x509 -req -in "$T/$1.csr" -CA "$T/$3.pem" -CAkey "$T/$3.key" \
    -CAcreateserial -days 3650 "-$4" -extfile "$T/ext" -out "$T/$1.pem" 2>/dev/null
}
bag() { # out cert...
  out=$1; shift
  args=""
  for c in "$@"; do args="$args -certfile $T/$c.pem"; done
  # shellcheck disable=SC2086
  openssl crl2pkcs7 -nocrl $args -outform DER -out "$out"
}

# rsa: root -> ca -> leaf, SHA-256, plus an impostor CA with the real CA's
# name but its own key.
key root rsa; root root "Chain Root" sha256
key ca rsa; issue ca "Chain CA" root sha256
key leaf rsa; issue leaf "Chain Leaf" ca sha256
# SET OF is DER-sorted on decode, so bag order is not under our control.
# Two bags make the test order-independent: with only the impostor present the
# walk must try and reject it; with both present it must pick the real CA.
key impostor rsa; root impostor "Chain CA" sha256
bag rsa-impostor-only.p7b leaf impostor
bag rsa-impostor-and-real.p7b leaf impostor ca root

# sha1: legacy RSA links signed with SHA-1.
key s1root rsa; root s1root "SHA1 Root" sha1
key s1leaf rsa; issue s1leaf "SHA1 Leaf" s1root sha1
bag sha1.p7b s1leaf s1root

# ecdsa: P-384 root signs a P-256 CA (ecdsa-with-SHA384), which signs a leaf
# (ecdsa-with-SHA256).
key eroot p384; root eroot "EC Root" sha384
key eca p256; issue eca "EC CA" eroot sha384
key eleaf p256; issue eleaf "EC Leaf" eca sha256
bag ecdsa.p7b eleaf eca eroot

# unsupported: a P-256 CA signing with SHA-384 (an off-pair the verifier
# declines), so the walk stops at the leaf.
key uca p256; root uca "Offpair CA" sha256
key uleaf rsa; issue uleaf "Offpair Leaf" uca sha384
bag offpair.p7b uleaf uca

# depth: ten certificates, each signing the next; the walk caps at eight.
key d0 rsa; root d0 "Depth 0" sha256
prev=d0
for i in 1 2 3 4 5 6 7 8 9; do
  key "d$i" rsa; issue "d$i" "Depth $i" "$prev" sha256; prev="d$i"
done
bag depth.p7b d9 d8 d7 d6 d5 d4 d3 d2 d1 d0

# loop: A and B certify each other (cross-signing); a leaf under A must not
# walk forever.
key la rsa; key lb rsa
root la "Loop A" sha256; root lb "Loop B" sha256
issue la "Loop A" lb sha256   # A, issued by B
cp "$T/la.pem" "$T/la-by-b.pem"
root la "Loop A" sha256       # restore A self-cert to sign B
issue lb "Loop B" la sha256   # B, issued by A
cp "$T/la-by-b.pem" "$T/la.pem"
key lleaf rsa; issue lleaf "Loop Leaf" la sha256
bag loop.p7b lleaf la lb
