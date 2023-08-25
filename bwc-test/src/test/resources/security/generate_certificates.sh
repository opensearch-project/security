#!/bin/sh
# Root CA

openssl genrsa -out root-ca-key.pem 2048
openssl req -addext basicConstraints=critical,CA:TRUE,pathlen:1 -new -x509 -sha256 -key root-ca-key.pem -subj "/DC=com/DC=example/O=Example Com Inc./OU=Example Com Inc. Root CA/CN=Example Com Inc. Root CA, CN = Example Com Inc. Root CA" -out root-ca.pem -days 730

# kirk cert
openssl genrsa -out kirk-key-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in kirk-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out kirk-key.pem
openssl req -new -key kirk-key.pem -subj "/C=de/L=test/O=client/OU=client/CN=kirk" -out kirk.csr
openssl x509 -req -in kirk.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out kirk.pem -days 730


openssl genrsa -out esnode-key-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in esnode-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out esnode-key.pem
openssl req -new -key esnode-key.pem -subj "/C=de/L=test/O=node/OU=node/CN=node-0.example.com" -out esnode.csr
# openssl x509 -req -days 3650 -extfile <(printf "subjectAltName=DNS:node-0.example.com,DNS:localhost,IP:::1,IP:127.0.0.1,RID:1.2.3.4.5.5") -in esnode.csr -out esnode.pem -CA root-ca.pem -CAkey root-ca-key.pem


# Cleanup
rm kirk-key-temp.pem
rm kirk.csr
rm signing-key-temp.pem
rm signing.csr
# rm esnode-key-temp.pem
# rm esnode.csr
# rm esnode.ext