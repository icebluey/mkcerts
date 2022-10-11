#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

umask 022
set -e

mkdir -p domainCerts/ca/newcerts
mkdir domainCerts/private domainCerts/certs
touch domainCerts/ca/index.txt
echo 0001 > domainCerts/ca/serial

openssl genrsa -out domainCerts/private/domain.key 4096
#openssl ecparam -genkey -noout -name P-384 -out domainCerts/private/domain.key

rm -f /tmp/openssl_domain.cnf
echo
sleep 1

cat << EOF > /tmp/openssl_domain.cnf
# cert
[ ca ]
default_ca  = CA_default
[ CA_default ]
dir = ./domainCerts/ca
certs = \$dir/certs
crl_dir = \$dir/crl
database = \$dir/index.txt
#unique_subject = no
new_certs_dir = \$dir/newcerts
serial = \$dir/serial
crlnumber = \$dir/crlnumber
crl = \$dir/crl.pem
default_md  = default
[ policy_anything ]
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

[ server_cert ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName=@alt_names

[alt_names]
DNS.1 = *.test.com
DNS.2 = test.com
EOF

#DNS.1 = localhost
#DNS.2 = localhost.localdomain
#IP.1 = 127.0.0.1

echo
sleep 1

openssl req -new -sha256 -config /tmp/openssl_domain.cnf \
-key domainCerts/private/domain.key -out domainCerts/certs/domain.csr \
-subj "/CN=www.test.com"

echo
sleep 1

openssl ca -md sha256 -days 730 -notext -config /tmp/openssl_domain.cnf \
-extensions server_cert -policy policy_anything \
-in domainCerts/certs/domain.csr -out domainCerts/certs/domain.crt \
-cert intermediate/certs/middle.crt -keyfile intermediate/private/middle.key

echo
sleep 1

cat domainCerts/certs/domain.crt > domainCerts/certs/fullchain.crt
echo >> domainCerts/certs/fullchain.crt
cat domainCerts/certs/domain.crt >> domainCerts/certs/fullchain.crt

rm -f /tmp/openssl_domain.cnf
rm -f domainCerts/certs/domain.csr
rm -fr domainCerts/ca
echo
printf '\033[01;32m%s\033[m\n' '  certificate created successfully'
echo
exit


