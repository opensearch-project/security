# Script to generate certificates for SecurityAdmin Tests

```
openssl genrsa -out root-ca-key.pem 2048
openssl req -x509 -sha256 -new -nodes -key root-ca-key.pem -subj "/DC=com/DC=example/O=Example Com Inc./OU=Example Com Inc. Root CA/CN=Example Com Inc. Root CA" -days 3650 -out root-ca.pem
openssl genrsa -out signing-key.pem 2048
openssl req -x509 -sha256 -new -nodes -CA root-ca.pem -CAkey root-ca-key.pem -key signing-key.pem -subj "/DC=com/DC=example/O=Example Com Inc./OU=Example Com Inc. Signing CA/CN=Example Com Inc. Signing CA" -days 3650 -out signing.pem

openssl genrsa -out node-key-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in node-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node.key.pem
openssl req -new -key node.key.pem -subj "/C=DE/L=Test/O=Test/OU=SSL/CN=node-1.example.com" -out node.csr
openssl x509 -req -days 3650 -extfile <(printf "subjectAltName=DNS:node-1.example.com,IP:127.0.0.1") -in node.csr -out node.crt.pem -CA signing.pem -CAkey signing-key.pem

# CN=kirk,OU=client,O=client,L=Test,C=DE
openssl genrsa -out kirk-key-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in kirk-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out kirk.key.pem
openssl req -new -key kirk.key.pem -subj "/C=DE/L=Test/O=client/OU=client/CN=kirk" -out kirk.csr
openssl x509 -req -days 3650 -in kirk.csr -out kirk.crt.pem -CA signing.pem -CAkey signing-key.pem
```

For `kirk.crt.pem` and `node.crt.pem` all certificates in the chain including `root-ca.pem` and `signing.pem` need to be included in the file.

When bundling the certificates together in the same file the root certificate is placed at the bottom and the lowest level certificate (the node certificate) on the top.
