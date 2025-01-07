### Check certificates
```
openssl x509 -text -noout -in rootCA.crt
openssl x509 -text -noout -in intermediateCA.crt
openssl x509 -text -noout -in server.crt
```
### Read private key
```
openssl pkey -text -noout -in rootCA.key
openssl asn1parse -i -in rootCA.key
```
### 验证
```
openssl verify -verbose -CAfile root/certs/rootCA.crt intermediate/certs/intermediateCA.crt
openssl verify -verbose -CAfile <(cat intermediate/certs/intermediateCA.crt root/certs/rootCA.crt) serverCerts/certs/server.crt
openssl verify -verbose -CAfile root/certs/rootCA.crt -untrusted intermediate/certs/intermediateCA.crt serverCerts/certs/server.crt

Check a key:
Check the SSL key and verify the consistency

openssl rsa -in server.key -check

Check a CSR:
Verify the CSR and print CSR data filled in when generating the CSR
openssl req -text -noout -verify -in server.csr

Verify a certificate and key matches

These two commands print out md5 checksums of the certificate and key; the checksums can be compared to verify that the certificate and key match.

openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5

```


### 添加和信任自己的自定义证书
确保证书是 PEM 格式，文件扩展名通常为 .crt 或 .pem。如果证书是其他格式（如 .der），需要先转换：
```
openssl x509 -inform DER -in your-cert.der -out your-cert.crt
```

RHEL/CentOS
```
cp your-root-ca.crt /etc/pki/ca-trust/source/anchors/
update-ca-trust


ls -la /etc/pki/tls/cert.pem
/etc/pki/tls/cert.pem -> /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem

update-ca-trust 后，your-root-ca.crt 会被添加到 cert.pem 中的的最前端，以 CN 作为备注。
例如 -subj "/C=US/OU=Root CA OU/CN=Root CA CN" , 则
# Root CA CN
-----BEGIN CERTIFICATE-----
```

Debian/Ubuntu
```
cp your-root-ca.crt /usr/local/share/ca-certificates/
update-ca-certificates
```

Diffie-Hellman parameters
```
openssl dhparam -out dhparam.pem 3072
openssl dhparam -dsaparam -out dhparam.pem 4096
```

### 生成完整的证书链 Fullchain
生成完整的证书链（通常称为 "fullchain"）涉及将最终实体证书（例如服务器证书）与中间 CA 证书（以及有时包括根 CA 证书）连接在一起。这在配置 TLS/SSL 服务时尤其重要，因为它允许客户端验证服务器证书的完整签名路径。

在你已经有了根 CA、中间 CA 和服务器证书之后，你可以按以下步骤生成 "fullchain" 文件：

1. **定位证书文件**：
   - 确定服务器证书文件的位置（例如 `server.crt`）。
   - 确定中间 CA 证书文件的位置（例如 `intermediateCA.crt`）。
   - （可选）确定根 CA 证书文件的位置（例如 `rootCA.crt`）。

2. **合并证书**：
   - 使用命令行工具（如 `cat` 在 Linux 或 macOS 上）合并这些文件。通常，服务器证书在前，其次是中间 CA，最后是根 CA（根 CA 通常不包括在内，因为它应该已经被客户端信任）。
   - 例如：
     ```
     cat server.crt intermediateCA.crt > fullchain.crt
     ```
     或者，如果你也想包括根 CA：
     ```
     cat server.crt intermediateCA.crt rootCA.crt > fullchain.crt
     ```

3. **使用 Fullchain**：
   - 将生成的 `fullchain.crt` 文件用于你的服务器配置，例如在 Apache、Nginx 或其他支持 TLS/SSL 的服务中。

4. 注意事项

- **证书顺序**：在 `fullchain.crt` 文件中，证书的顺序很重要。通常，服务器证书放在最前面，其次是中间 CA，然后是根 CA（如果包括的话）。
- **根 CA 包含**：在大多数情况下，不需要在 `fullchain.crt` 文件中包含根 CA 证书，因为客户端（如浏览器）通常已经内置了对它的信任。
- **安全性**：`fullchain.crt` 文件不应包含任何私钥信息。它只应包含公开的证书数据。

通过将这些证书正确地串联起来，你就可以确保客户端可以验证服务器证书的完整签名路径，从而建立安全连接。

### PKCS #12
```
生成 PFX 文件
要设置密码，不然 keytool 转化 .pfx 会报错
openssl pkcs12 -export -out complete.pfx -inkey server.key -in fullchain.crt
openssl pkcs12 -export -out complete.pfx -inkey server.key -in fullchain.crt -certfile more.cert

验证 PFX 文件
openssl pkcs12 -info -in complete.pfx -nodes

仅显示私钥
openssl pkcs12 -in complete.pfx -nocerts -nodes

提取完整证书链
openssl pkcs12 -in complete.pfx -nokeys

仅显示服务器证书
openssl pkcs12 -in complete.pfx -nokeys -clcerts

keytool -importkeystore -srckeystore complete.pfx -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS
keytool -importkeystore -srckeystore complete.pfx -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype PKCS12

```

