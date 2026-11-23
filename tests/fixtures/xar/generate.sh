#!/bin/sh
# Regenerates rsa-sha256.xar, the xar signature fixture for formats::xar: a
# minimal archive whose TOC checksum is SHA-256 (header checksum algorithm
# 3, named in a 64-byte header) and whose only signature is the bare RSA
# one, PKCS #1 v1.5 over the checksum, with a self-signed certificate in its
# KeyInfo. The heap holds the checksum at 0, the signature at 32, and a
# 5-byte member. The key is throwaway and not kept.
set -eu
cd "$(dirname "$0")"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/key.pem" 2>/dev/null
openssl req -x509 -new -key "$T/key.pem" -subj "/CN=filefacts xar fixture/O=Filefacts Fixtures" \
  -days 3650 -sha256 -out "$T/cert.pem" 2>/dev/null
CERT=$(openssl x509 -in "$T/cert.pem" -outform DER | base64 | tr -d '\n')
cat > "$T/toc.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<xar>
 <toc>
  <checksum style="sha256"><offset>0</offset><size>32</size></checksum>
  <signature style="RSA"><offset>32</offset><size>256</size>
   <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>
    <X509Certificate>$CERT</X509Certificate>
   </X509Data></KeyInfo>
  </signature>
  <file id="1"><name>hello</name><type>file</type>
   <data><offset>288</offset><size>5</size><length>5</length><encoding style="application/octet-stream"/></data>
  </file>
 </toc>
</xar>
XML
python3 -I -c 'import sys, zlib; sys.stdout.buffer.write(zlib.compress(open(sys.argv[1], "rb").read()))' \
  "$T/toc.xml" > "$T/toc.z"
openssl dgst -sha256 -binary "$T/toc.z" > "$T/checksum"
openssl pkeyutl -sign -inkey "$T/key.pem" -pkeyopt digest:sha256 -in "$T/checksum" -out "$T/sig"
python3 -I -c '
import struct, sys
toc, checksum, sig = (open(p, "rb").read() for p in sys.argv[1:4])
header = struct.pack(">4sHHQQI", b"xar!", 64, 1, len(toc), 0, 3) + b"sha256".ljust(36, b"\0")
sys.stdout.buffer.write(header + toc + checksum + sig + b"hello")
' "$T/toc.z" "$T/checksum" "$T/sig" > rsa-sha256.xar
