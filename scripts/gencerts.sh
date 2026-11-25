#!/usr/bin/env bash
# Generates a local PKI for the lab:
#   ca.crt/ca.key            - trusted local root CA (LR6 Demo Root CA)
#   server.crt/server.key    - server certificate (CN=localhost, SAN=localhost,127.0.0.1, EKU=serverAuth)
#   client.crt/client.key    - client certificate for optional mTLS (EKU=clientAuth)
#   rogue_ca.crt/rogue_ca.key, rogue_client.* - "foreign" CA for negative tests
set -euo pipefail
CERT_DIR="${CERT_DIR:-certs}"
DAYS_CA=3650
DAYS_LEAF=397
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"
umask 077

make_ca () {   # $1 = file prefix, $2 = CN
  openssl ecparam -name secp384r1 -genkey -noout -out "$1.key"
  openssl req -x509 -new -key "$1.key" -sha384 -days $DAYS_CA \
    -subj "/C=UA/O=KUBG LR6/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$1.crt"
}

make_leaf () { # $1 = prefix, $2 = CN, $3 = CA prefix, $4 = extensions
  openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"
  openssl req -new -key "$1.key" -subj "/C=UA/O=KUBG LR6/CN=$2" -out "$1.csr"
  printf "%b" "$4" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$3.crt" -CAkey "$3.key" -CAcreateserial \
    -days $DAYS_LEAF -sha256 -extfile "$1.ext" -out "$1.crt"
  rm -f "$1.csr" "$1.ext"
}

make_ca ca "LR6 Demo Root CA"
make_leaf server localhost ca \
"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nauthorityKeyIdentifier=keyid\n"
make_leaf client demo-client ca \
"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nauthorityKeyIdentifier=keyid\n"

# Negative-test material: a CA that nobody trusts
make_ca rogue_ca "Rogue Untrusted CA"
make_leaf rogue_client rogue-client rogue_ca \
"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"

chmod 644 ./*.crt
echo "[gencerts] Certificates created in $(pwd):"
ls -1 ./*.crt
openssl verify -CAfile ca.crt server.crt client.crt
