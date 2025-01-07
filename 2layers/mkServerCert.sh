#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

umask 022
set -e

_output="serverCerts"

mkdir -p "${_output}"/ca/newcerts
mkdir "${_output}"/private "${_output}"/certs
touch "${_output}"/ca/index.txt
echo 0001 > "${_output}"/ca/serial

openssl genrsa -out "${_output}"/private/"${_output}".key 2048
#openssl ecparam -genkey -noout -name P-384 -out "${_output}"/private/"${_output}".key

rm -f /tmp/openssl_server.cnf
echo
sleep 1

cat << EOF > /tmp/openssl_server.cnf
# cert
[ca]
default_ca = CA_default
[CA_default]
dir = ./${_output}/ca
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

openssl req -new -${_digest_algo} -config /tmp/openssl_server.cnf \
-key "${_output}"/private/"${_output}".key -out "${_output}"/certs/"${_output}".csr \
-subj "/CN=www.test.internal"

echo
sleep 1

# 2 years, 730 = 2*365
openssl ca -md ${_digest_algo} -days 730 -notext -config /tmp/openssl_server.cnf \
-extensions server_cert -policy policy_anything \
-in "${_output}"/certs/"${_output}".csr -out "${_output}"/certs/"${_output}".crt \
-cert root/certs/ca.crt -keyfile root/private/ca.key

echo
sleep 1

rm -f /tmp/openssl_server.cnf
rm -f "${_output}"/certs/"${_output}".csr
rm -fr "${_output}"/ca
echo
printf '\033[01;32m%s\033[m\n' '  Server cert created successfully'
echo
exit

