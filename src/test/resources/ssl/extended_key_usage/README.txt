### Commands to generate certs in this folder

# Root CA
openssl genrsa -out root-ca-key.pem 2048
openssl req -new -x509 -sha256 -key root-ca-key.pem -days 3000 -out root-ca.pem

# Node server cert
openssl genrsa -out node-key-server-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in node-key-server-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node-key-server.pem
openssl req -new -key node-key-server.pem -out node-server.csr
openssl x509 -req -in node-server.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -extfile ext.cfg -extensions server_exts -days 3000 -out node-server.pem

# Node client cert
openssl genrsa -out node-key-client-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in node-key-client-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node-key-client.pem
openssl req -new -key node-key-client.pem -out node-client.csr
openssl x509 -req -in node-client.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -extfile ext.cfg -extensions client_exts -days 3000 -out node-client.pem

## Create keystore and truststore

# prapare combined cert to import into keystore
cat node-client.pem root-ca.pem > import-client.pem
cat node-server.pem root-ca.pem > import-server.pem

# when prompted use password 'changeit'
openssl pkcs12 -export -in import-client.pem -inkey node-key-client.pem -name node-0-client > node-client.p12
openssl pkcs12 -export -in import-server.pem -inkey node-key-server.pem -name node-0-server > node-server.p12
keytool -importkeystore -srckeystore node-client.p12 -destkeystore node-0-keystore.jks -srcstoretype pkcs12 -alias node-0-client 
keytool -importkeystore -srckeystore node-server.p12 -destkeystore node-0-keystore.jks -srcstoretype pkcs12 -alias node-0-server 

# create truststore
keytool -import -trustcacerts -file root-ca.pem -alias root-ca -keystore truststore.jks 

# Cleanup
rm node-key-server-temp.pem
rm node-key-client-temp.pem
rm node-server.csr
rm node-client.csr
rm root-ca.srl
rm import-*
rm node-client.p12
rm node-server.p12
