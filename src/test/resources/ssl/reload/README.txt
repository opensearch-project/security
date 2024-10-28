Commands to generate node-new-ca.crt.pem, node-new-ca.key.pem, secondary-root-ca.pem, secondary-signing-ca.pem:

# generate new secondary root CA
openssl genrsa -out secondary-root-ca-key.pem 2048
openssl req -new -x509 -sha256 -days 3650 -key secondary-root-ca-key.pem -subj "/DC=com/DC=example/O=Example Com Inc./OU=Example Com Inc. Secondary Root CA/CN=Example Com Inc. Secondary Root CA" -addext "basicConstraints = critical,CA:TRUE" -addext "keyUsage = critical, digitalSignature, keyCertSign, cRLSign" -addext "subjectKeyIdentifier = hash" -addext "authorityKeyIdentifier = keyid:always,issuer:always" -out secondary-root-ca.pem

# generate new secondary signing CA, signed by the new secondary root CA

openssl genrsa -out secondary-signing-ca-key-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in secondary-signing-ca-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out secondary-signing-ca-key.pem
openssl req -new -key secondary-signing-ca-key.pem -subj "/DC=com/DC=example/O=Example Com Inc./OU=Example Com Inc. Secondary Signing CA/CN=Example Com Inc. Secondary Signing CA" -out secondary-signing-ca-key.csr
printf "basicConstraints = critical,CA:TRUE" > secondary-signing-ca_ext.conf
printf "basicConstraints = critical,CA:TRUE\nkeyUsage = critical, digitalSignature, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always,issuer:always" > secondary-signing-ca_ext.conf
openssl x509 -req -in secondary-signing-ca-key.csr -out secondary-signing-ca.pem -CA secondary-root-ca.pem -CAkey secondary-root-ca-key.pem -CAcreateserial -days 3650 -extfile secondary-signing-ca_ext.conf

# generate a new node cert, signed by the new secondary signing key CA
openssl genrsa -out node-new-ca-key-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in node-new-ca-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node-new-ca.key.pem
openssl req -new -key node-new-ca.key.pem -subj "/C=DE/L=Test/O=Test/OU=SSL/CN=node-1.example.com" -out node-new-ca.csr
printf "subjectAltName = RID:1.2.3.4.5.5, DNS:node-1.example.com, DNS:localhost, IP:127.0.0.1" > node-new-ca_ext.conf
openssl x509 -req -in node-new-ca.csr -out node-new-ca.pem -CA secondary-signing-ca.pem -CAkey secondary-signing-ca-key.pem -CAcreateserial -days 3650 -extfile node-new-ca_ext.conf

cat node-new-ca.pem > node-new-ca.crt.pem
cat secondary-signing-ca.pem >> node-new-ca.crt.pem
cat secondary-root-ca.pem >> node-new-ca.crt.pem

# for tests to pass, the new secondary-signing-ca.pem and secondary-root-ca.pem keys should also be added to the truststore.jks file, e.g.:
keytool -import -alias secondary-root-ca -file secondary-root-ca.pem -storetype JKS -keystore truststore.jks
keytool -import -alias secondary-signing-ca -file secondary-signing-ca.pem -storetype JKS -keystore truststore.jks
