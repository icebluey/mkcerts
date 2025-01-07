#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

umask 022
set -e

mkdir -p intermediate/private intermediate/certs
mkdir -p intermediate/ca/newcerts
touch intermediate/ca/index.txt
echo 0001 > intermediate/ca/serial

openssl genrsa -out intermediate/private/intermediateCA.key 2048

#openssl genrsa -out intermediate/private/intermediateCA.key 4096

#openssl ecparam -genkey -noout -name P-384 -out intermediate/private/intermediateCA.key

rm -f /tmp/openssl_intermediateCA.cnf
sleep 1

cat << EOF > /tmp/openssl_intermediateCA.cnf
# intermediate CA
[ca]
default_ca = CA_default
[CA_default]
dir = ./intermediate/ca
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

# Root CA
[req]
req_extensions = v3_req
x509_extensions = v3_ca
distinguished_name = dn
[dn]
[v3_req]
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
basicConstraints = critical,CA:TRUE,pathlen:0
subjectKeyIdentifier = hash
[v3_ca]
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
basicConstraints = critical,CA:TRUE,pathlen:0
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
echo
sleep 1

openssl req -new -sha256 -config /tmp/openssl_intermediateCA.cnf \
-key intermediate/private/intermediateCA.key -out intermediate/certs/intermediateCA.csr \
-subj "/C=US/CN=SHA2 Extended Validation Server CA"

echo
sleep 1

# 25 years, 9125 = 25*365
openssl ca -md sha256 -days 9125 -notext -config /tmp/openssl_intermediateCA.cnf \
-extensions v3_ca -policy policy_anything \
-in intermediate/certs/intermediateCA.csr -out intermediate/certs/intermediateCA.crt \
-cert root/certs/rootCA.crt -keyfile root/private/rootCA.key

echo
sleep 1
rm -f /tmp/openssl_intermediateCA.cnf
rm -f intermediate/certs/intermediateCA.csr
rm -fr intermediate/ca
echo
printf '\033[01;32m%s\033[m\n' '  Intermediate CA created successfully'
echo
exit

#openssl verify -CAfile certs/rootCA.crt intermediate/certs/intermediateCA.crt




