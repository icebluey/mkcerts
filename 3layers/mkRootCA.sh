#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

[ -f openssl ] && _OPENSSL_BIN='./openssl'

umask 022
set -e

mkdir -p root/private root/certs

# RSA4096 Root Key
${_OPENSSL_BIN:-openssl} genrsa -out root/private/rootCA.key 4096

# RSA2048 Root Key
#${_OPENSSL_BIN:-openssl} genrsa -out root/private/rootCA.key 2048

# ECC P384 Root Key
#${_OPENSSL_BIN:-openssl} ecparam -genkey -noout -name P-384 -out root/private/rootCA.key

# Encrypted Root Key
#${_OPENSSL_BIN:-openssl} genrsa -aes256 -out root/private/rootCA.key 4096

#${_OPENSSL_BIN:-openssl} ecparam -genkey -noout -name P-384 | openssl ec -aes256 -out root/private/rootCA.key
# or
#${_OPENSSL_BIN:-openssl} ecparam -genkey -noout -name P-384 | openssl pkey -aes256 -out root/private/rootCA.key

rm -f /tmp/openssl_rootCA.cnf
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
-key root/private/rootCA.key -out root/certs/rootCA.csr \
-subj "/C=US/OU=Root CA/CN=Root CA"

echo
sleep 1

# 30 years, 10950 = 30*365
${_OPENSSL_BIN:-openssl} x509 -req -${_digest_algo} -days 10950 -extfile /tmp/openssl_rootCA.cnf -extensions v3_ca \
-signkey root/private/rootCA.key -in root/certs/rootCA.csr -out root/certs/rootCA.crt

echo
sleep 1

rm -f /tmp/openssl_rootCA.cnf
rm -f root/certs/rootCA.csr
echo
printf '\033[01;32m%s\033[m\n' '  Root CA created successfully'
echo
exit

#openssl asn1parse -i -in root/private/rootCA.key
#openssl req -text -noout -in root/certs/rootCA.csr
#openssl x509 -text -noout -in root/certs/rootCA.crt

