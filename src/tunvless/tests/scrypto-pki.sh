#!/bin/sh
# Issue the test PKI for tests/scryptomatch.c and print tests/scrypto-pki.h.
#
#     sh tests/scrypto-pki.sh > tests/scrypto-pki.h
#
# OpenSSL issues the certificates and signatures, and wolfSSL behind the scrypto layer checks them:
# the test catches a mistake both in our use of the library and in the library itself, instead of
# checking the library against itself. Keys are new on every run, so the file is only ever
# regenerated whole by this script, never edited by hand.
#
# Contents: root (EC P-256) -> intermediate (RSA 2048, pathlen 0) -> leaves: EC P-256 with SAN
# good.example, *.wild.example and IP 192.0.2.7; RSA 2048 with SAN rsa.example (PKCS#1 v1.5
# signature and PSS with salt 32, 20 and 0); P-384 directly under the root; a "fake CA", a leaf
# without the CA flag that signs another leaf (a chain through it must fail); an expired leaf
# (2020-2021); an unrelated root. The rest are valid for 30 years from issue.
set -eu
command -v openssl >/dev/null || { echo "scrypto-pki: needs openssl" >&2; exit 2; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cd "$W"
printf '%s\n' '[req]' 'distinguished_name=dn' '[dn]' \
  '[ca]' 'basicConstraints=critical,CA:TRUE' 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' \
  '[inter]' 'basicConstraints=critical,CA:TRUE,pathlen:0' 'keyUsage=critical,keyCertSign,cRLSign' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' \
  '[leaf]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' \
  'subjectAltName=DNS:good.example,DNS:*.wild.example,IP:192.0.2.7' \
  '[rsaleaf]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' 'subjectAltName=DNS:rsa.example' \
  '[p384]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' 'subjectAltName=DNS:p384.example' \
  '[fakeca]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' 'subjectAltName=DNS:fake.example' \
  '[fakeleaf]' 'basicConstraints=critical,CA:FALSE' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' \
  'subjectAltName=DNS:good.example' > ext.cnf
printf '%s\n' '[ca]' 'default_ca=d' '[d]' 'dir=.' 'database=./index.txt' 'new_certs_dir=./new' 'serial=./serial' \
  'default_md=sha256' 'policy=pol' 'copy_extensions=none' 'unique_subject=no' '[pol]' 'commonName=supplied' \
  '[expired]' 'basicConstraints=critical,CA:FALSE' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' \
  'subjectAltName=DNS:good.example' > ca.cnf
D=10957
q() { "$@" >/dev/null 2>&1; }
q openssl ecparam -name prime256v1 -genkey -noout -out root.key
q openssl req -x509 -new -key root.key -sha256 -days $D -subj "/CN=steer test root" -extensions ca -config ext.cnf -out root.pem
q openssl ecparam -name prime256v1 -genkey -noout -out other.key
q openssl req -x509 -new -key other.key -sha256 -days $D -subj "/CN=steer other root" -extensions ca -config ext.cnf -out other.pem
q openssl genrsa -out inter.key 2048
q openssl req -new -key inter.key -subj "/CN=steer test intermediate" -config ext.cnf -out inter.csr
q openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key -set_serial 2 -sha256 -days $D -extfile ext.cnf -extensions inter -out inter.pem
leaf() { # name extension-section issuer serial
    q openssl req -new -key "$1.key" -subj "/CN=$1" -config ext.cnf -out "$1.csr"
    q openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -set_serial "$4" -sha256 -days $D \
        -extfile ext.cnf -extensions "$2" -out "$1.pem"
}
q openssl ecparam -name prime256v1 -genkey -noout -out leaf.key;     leaf leaf leaf inter 10
q openssl genrsa -out rsaleaf.key 2048;                              leaf rsaleaf rsaleaf inter 11
q openssl ecparam -name secp384r1 -genkey -noout -out p384.key;      leaf p384 p384 root 12
q openssl ecparam -name prime256v1 -genkey -noout -out fakeca.key;   leaf fakeca fakeca inter 13
q openssl ecparam -name prime256v1 -genkey -noout -out fakeleaf.key; leaf fakeleaf fakeleaf fakeca 14
mkdir new
: > index.txt
echo 20 > serial
q openssl ecparam -name prime256v1 -genkey -noout -out expired.key
q openssl req -new -key expired.key -subj "/CN=expired" -config ext.cnf -out expired.csr
q openssl ca -batch -config ca.cnf -cert inter.pem -keyfile inter.key -in expired.csr -out expired.pem \
    -startdate 20200101000000Z -enddate 20210101000000Z -extensions expired -notext
printf 'steer scrypto' > msg
q openssl dgst -sha256 -sign leaf.key -out s.ecdsa256 msg
q openssl dgst -sha384 -sign p384.key -out s.ecdsa384 msg
q openssl dgst -sha256 -sign rsaleaf.key -out s.pkcs1 msg
q openssl dgst -sha256 -sign rsaleaf.key -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -out s.pss256 msg
q openssl dgst -sha384 -sign rsaleaf.key -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 -out s.pss384s20 msg
q openssl dgst -sha256 -sign rsaleaf.key -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:0 -out s.pss256s0 msg

echo "/* Test PKI for tests/scryptomatch.c: sh tests/scrypto-pki.sh > tests/scrypto-pki.h"
echo " * ($(openssl version | cut -d' ' -f1-2), $(date -u +%Y-%m-%d)). Generated; do not edit by hand, regenerate it whole. */"
echo "#ifndef STEER_TESTS_SCRYPTO_PKI_H"
echo "#define STEER_TESTS_SCRYPTO_PKI_H"
for c in root inter leaf rsaleaf p384 fakeca fakeleaf expired other; do
    echo "static const char PEM_$(echo $c | tr a-z A-Z)[] ="
    sed 's/.*/    "&\\n"/' $c.pem
    echo "    ;"
done
for s in ecdsa256 ecdsa384 pkcs1 pss256 pss384s20 pss256s0; do
    echo "static const char SIG_$(echo $s | tr a-z A-Z)[] ="
    od -An -v -tx1 s.$s | tr -d ' \n' | fold -w 60 | sed 's/.*/    "&"/'
    echo
    echo "    ;"
done
echo "#endif"
