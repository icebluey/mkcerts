#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

umask 022
set -e

mkdir -p intermediate/private intermediate/certs
mkdir -p intermediate/ca/newcerts
touch intermediate/ca/index.txt
echo 0001 > intermediate/ca/serial

openssl genrsa -out intermediate/private/middle.key 4096

rm -f /tmp/openssl_IntermediateCA.cnf
echo
sleep 1

cat << EOF > /tmp/openssl_IntermediateCA.cnf
# intermediate CA
[ ca ]
default_ca  = CA_default
[ CA_default ]
dir = ./intermediate/ca
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

# Root CA
[req]
req_extensions = v3_req
x509_extensions = v3_ca
distinguished_name = dn
[dn]
[v3_req]
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
basicConstraints = critical,CA:TRUE,pathlen:0
subjectKeyIdentifier=hash
[ v3_ca ]
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
basicConstraints = critical,CA:TRUE,pathlen:0
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
echo
sleep 1

openssl req -new -sha256 -config /tmp/openssl_IntermediateCA.cnf \
-key intermediate/private/middle.key -out intermediate/certs/middle.csr \
-subj "/C=US/CN=SHA2 Extended Validation Server CA"

echo
sleep 1

openssl ca -md sha256 -days 3650 -notext -config /tmp/openssl_IntermediateCA.cnf \
-extensions v3_ca -policy policy_anything \
-in intermediate/certs/middle.csr -out intermediate/certs/middle.crt \
-cert root/certs/RootCA.crt -keyfile root/private/RootCA.key

echo
sleep 1
rm -f /tmp/openssl_IntermediateCA.cnf
rm -f intermediate/certs/middle.csr
rm -fr intermediate/ca
echo
printf '\033[01;32m%s\033[m\n' '  IntermediateCA created successfully'
echo
exit

#openssl verify -CAfile certs/RootCA.cer intermediate/certs/middle.cer




