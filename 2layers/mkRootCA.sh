#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

[ -f openssl ] && _OPENSSL_BIN='./openssl'

umask 022
set -e

mkdir -p root/private root/certs

${_OPENSSL_BIN:-openssl} genrsa -out root/private/ca.key 4096

#${_OPENSSL_BIN:-openssl} genrsa -out root/private/ca.key 2048

#${_OPENSSL_BIN:-openssl} genrsa -aes256 -out root/private/ca.key 4096

#${_OPENSSL_BIN:-openssl} ecparam -genkey -noout -name P-384 -out root/private/ca.key

rm -f /tmp/openssl_rootCA.cnf
echo
sleep 1
cat << EOF > /tmp/openssl_rootCA.cnf
# Root CA
[req]
req_extensions = v3_req
x509_extensions = v3_ca
distinguished_name = dn
[dn]
[v3_req]
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
basicConstraints = critical,CA:TRUE
subjectKeyIdentifier = hash
[v3_ca]
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
basicConstraints = critical,CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
echo
sleep 1

_digest_algo='sha384'
#_digest_algo='sha256'

${_OPENSSL_BIN:-openssl} req -new -${_digest_algo} -config /tmp/openssl_rootCA.cnf \
-key root/private/ca.key -out root/certs/ca.csr \
-subj "/C=US/OU=Root CA/CN=Root CA"

echo
sleep 1

# 30 years, 10950 = 30*365
${_OPENSSL_BIN:-openssl} x509 -req -${_digest_algo} -days 10950 -extfile /tmp/openssl_rootCA.cnf -extensions v3_ca \
-signkey root/private/ca.key -in root/certs/ca.csr -out root/certs/ca.crt

echo
sleep 1

rm -f /tmp/openssl_rootCA.cnf
rm -f root/certs/ca.csr
echo
printf '\033[01;32m%s\033[m\n' '  Root CA created successfully'
echo
exit

#${_OPENSSL_BIN:-openssl} asn1parse -i -in root/private/ca.key
#${_OPENSSL_BIN:-openssl} req -text -noout -in root/certs/ca.csr
#${_OPENSSL_BIN:-openssl} x509 -text -noout -in root/certs/ca.crt

