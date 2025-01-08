#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

[ -f openssl ] && _OPENSSL_BIN='./openssl'

umask 022
set -e

mkdir -p serverCerts/ca/newcerts
mkdir serverCerts/private serverCerts/certs
touch serverCerts/ca/index.txt
echo 0001 > serverCerts/ca/serial

${_OPENSSL_BIN:-openssl} genrsa -out serverCerts/private/server.key 2048

#${_OPENSSL_BIN:-openssl} genrsa -out serverCerts/private/server.key 4096

#${_OPENSSL_BIN:-openssl} ecparam -genkey -noout -name P-384 -out serverCerts/private/server.key

rm -f /tmp/openssl_server.cnf
sleep 1

cat << EOF > /tmp/openssl_server.cnf
# cert
[ca]
default_ca = CA_default
[CA_default]
dir = ./serverCerts/ca
certs = \$dir/certs
crl_dir = \$dir/crl
database = \$dir/index.txt
#unique_subject = no
new_certs_dir = \$dir/newcerts
serial = \$dir/serial
crlnumber = \$dir/crlnumber
crl = \$dir/crl.pem
default_md = default
[policy_anything]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[req]
req_extensions = v3_req
distinguished_name = dn
[dn]
[v3_req]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth

[server_cert]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = *.test.internal
DNS.2 = test.internal
EOF

#DNS.1 = k8s-master1
#DNS.2 = localhost
#IP.1 = 192.168.10.1
#IP.2 = 127.0.0.1
#IP.3 = 0:0:0:0:0:0:0:1

echo
sleep 1

#_digest_algo='sha384'
_digest_algo='sha256'

${_OPENSSL_BIN:-openssl} req -new -${_digest_algo} -config /tmp/openssl_server.cnf \
-key serverCerts/private/server.key -out serverCerts/certs/server.csr \
-subj "/CN=www.test.internal"

echo
sleep 1

# 2 years, 730 = 2*365
${_OPENSSL_BIN:-openssl} ca -md ${_digest_algo} -days 730 -notext -config /tmp/openssl_server.cnf \
-extensions server_cert -policy policy_anything \
-in serverCerts/certs/server.csr -out serverCerts/certs/server.crt \
-cert intermediate/certs/intermediateCA.crt -keyfile intermediate/private/intermediateCA.key

echo
sleep 1

cat serverCerts/certs/server.crt intermediate/certs/intermediateCA.crt > serverCerts/certs/fullchain.crt

rm -f /tmp/openssl_server.cnf
rm -f serverCerts/certs/server.csr
rm -fr serverCerts/ca
echo
printf '\033[01;32m%s\033[m\n' '  Server Cert created successfully'
echo
exit

#${_OPENSSL_BIN:-openssl} verify -verbose -CAfile <(cat root/certs/rootCA.crt intermediate/certs/intermediateCA.crt) serverCerts/certs/fullchain.crt
#${_OPENSSL_BIN:-openssl} verify -verbose -CAfile <(cat root/certs/rootCA.crt intermediate/certs/intermediateCA.crt) serverCerts/certs/server.crt

