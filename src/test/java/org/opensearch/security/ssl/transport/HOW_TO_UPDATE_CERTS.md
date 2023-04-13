### In order to update certificates you will need to run these commands: 

```
# Generate root CA key and self-signed certificate

# Create a 2048 bit CA key
openssl genrsa -out root-ca-key.pem 2048

# Create new self-signed X.509 cert for root CA with subject and 10 year expiration
openssl req -x509 -new -key root-ca-key.pem -days 3650 -out root-ca.pem -subj "/CN=Example Com Inc. Root CA/OU=Example Com Inc. Root CA/O=Example Com Inc./DC=example/DC=com"

# Generate signing key and certificate signing request

# Create 2048 bit signing key
openssl genrsa -out signing-key.pem 2048

# Create new certificate signing request using signing-key.pem key and saves it to the signing.csr file
# Used for verifying applicant identity and issue cert if applicant is trustworthy
openssl req -new -key signing-key.pem -out signing.csr -subj "/CN=Example Com Inc. Signing CA/OU=Example Com Inc. Signing CA/O=Example Com Inc./DC=example/DC=com"

# Generate signed certificate using the root CA and the input CSR
# CAkey is the private key of the CA; -CAcreateserial generates a serial number to distinguish certificate from others created by same CA
openssl x509 -req -in signing.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -out signing.crt.pem -days 3650

# Verify new certificate
openssl verify -CAfile root-ca.pem signing.crt.pem

# Create a new 2048 bit RSA private key output to node-key-temp.pem file
openssl genrsa -out node-key-temp.pem 2048

# Converts private key in node-key-temp.pem to PKCS8 and writes it to the node.key.pem file
openssl pkcs8 -inform PEM -outform PEM -in node-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node.key.pem

# Generates a certificate signing request (CSR) for the private key stored in the node.key.pem file with the specified subject name "/C=DE/L=Test/O=Test/OU=SSL/CN=node-1.example.com" and outputs it to the file node.csr
openssl req -new -key node.key.pem -subj "/C=DE/L=Test/O=Test/OU=SSL/CN=node-1.example.com" -out node.csr

# Generates a certificate (node.crt.pem) for the node-1.example.com server, signed by the previously generated signing certificate (signing.pem), and adds a subject alternative name (SAN) to the certificate using an extension file.

openssl x509 -req -in node.csr -CA signing.crt.pem -CAkey signing-key.pem -CAcreateserial -out node.crt.pem -days 3650 -extfile <(printf "subjectAltName=DNS:node-1.example.com,DNS:localhost,IP:127.0.0.1,RID:1.2.3.4.5.5")

# Verify the signed certificate
pbcopy < root-ca.pem        # paste at top of signing.crt.pem
pbcopy < signing.crt.pem        # paste at top of node.crt.pem
openssl verify -verbose -CAfile root-ca.pem -untrusted signing.crt.pem node.crt.pem

# Create a new 2048 bit RSA private key output to node-new-key-temp.pem file
openssl genrsa -out node-new-key-temp.pem 2048

# Converts private key in node-new-key-temp.pem to PKCS8 and writes it to the node-new.key.pem file
openssl pkcs8 -inform PEM -outform PEM -in node-new-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node-new.key.pem
 
# Generates a certificate signing request (CSR) for the private key stored in the node-new.key.pem file with the specified subject name "/C=DE/L=Test/O=Test/OU=SSL/CN=node-1.example.com" and outputs it to the file node-new.csr
openssl req -new -key node-new.key.pem -subj "/C=DE/L=Test/O=Test/OU=SSL/CN=node-1.example.com" -out node-new.csr

# Generates a certificate (node-new.crt.pem) for the node-1.example.com server, signed by the previously generated signing certificate (signing.pem), and adds a subject alternative name (SAN) to the certificate using an extension file 
openssl x509 -req -days 3650 -extfile <(printf "subjectAltName=DNS:node-1.example.com,DNS:localhost,IP:127.0.0.1,RID:1.2.3.4.5.5") -in node-new.csr -out node-new.crt.pem -CA signing.crt.pem -CAkey signing-key.pem
 
# Create a new 2048 bit RSA private key output to node-wron-key-temp.pem 
openssl genrsa -out node-wrong-key-temp.pem 2048 

# Convert the private key in node-wrong-key-temp.pem into PKCS8 and write to node-wrong.key.pem 
openssl pkcs8 -inform PEM -outform PEM -in node-wrong-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node-wrong.key.pem 

# Generate a certificate signing request for the private key stored in the node-wrong.key.pem file 
openssl req -new -key node-wrong.key.pem -subj "/C=DE/L=Test/O=Test/OU=SSL/CN=node-2.example.com" -out node-wrong.csr
 
# Generates a certificate (node-wrong.crt.pem) for the node-2.example.com server, signed by the previously generated signing certificate (signing.pem), and adds a subject alternative name (SAN) to the certificate using an extension file 

openssl x509 -req -days 3650 -extfile <(printf "subjectAltName=DNS:node-2.example.com,DNS:localhost,IP:127.0.0.1,RID:1.2.3.4.5.5") -in node-wrong.csr -out node-wrong.crt.pem -CA signing.crt.pem -CAkey signing-key.pem
 
# Generate a new 2048 bit RSA key 
openssl genrsa -out kirk-key-temp.pem 2048
 
# Convert the generated krik-key-temp.pem into a PKCS8 key and save it as krik.key.pem 
openssl pkcs8 -inform PEM -outform PEM -in kirk-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out kirk.key.pem
 
# Generate a certificate signing request for the private key stored in kirk.key.pem 
openssl req -new -key kirk.key.pem -subj "/C=DE/L=Test/O=client/OU=client/CN=kirk" -out kirk.csr
 
# Generates a certificate (kirk.crt.pem) for the node-1.example.com server, signed by the previously generated signing certificate (signing.pem) 
openssl x509 -req -days 3650 -in kirk.csr -out kirk.crt.pem -CA signing.crt.pem -CAkey signing-key.pem

 
# Move the kirk certificate, signing-key, and certificate authority certificate into a bundle 
cat kirk.crt.pem signing.crt.pem root-ca.pem > kirk.crt.bundle.pem
 
# Convert the bundle into a pkcs12 file 
openssl pkcs12 -export -in kirk.crt.bundle.pem -inkey kirk.key.pem -name kirk > kirk.p12
 
# Generate a new private key for spock 
openssl genrsa -out spock-key-temp.pem 2048
 
# Convert the generated key into a PKCS8 format and save as spock.key.pem 
openssl pkcs8 -inform PEM -outform PEM -in spock-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out spock.key.pem
 
# Generate a certificate signing request for the private key stored in spock.key.pem
openssl req -new -key spock.key.pem -subj "/C=DE/L=Test/O=client/OU=client/CN=spock" -out spock.csr
 
# Generate a certificate signed by the signing certificate 
openssl x509 -req -days 3650 -in spock.csr -out spock.crt.pem -CA signing.crt.pem -CAkey signing-key.pem

# Move the spock certificate, private signing key, and root-ca certificate into a bundle 
cat spock.crt.pem signing-key.pem root-ca.pem > spock.crt.bundle.pem
 
# Convert the bundle into PKCS12 and save as spock.p12
openssl pkcs12 -export -in spock.crt.bundle.pem -inkey spock.key.pem -name spock > spock.p12

# Moves contents of spock.p12 into spock-keystore.jks
# password is: changeit
keytool -importkeystore -srckeystore spock.p12 -destkeystore spock-keystore.jks -srcstoretype pkcs12 -alias spock

# Moves contents of kirk.p12 into kirk-keystore.jks 
# password is: changeit
keytool -importkeystore -srckeystore kirk.p12 -destkeystore kirk-keystore.jks -srcstoretype pkcs12 -alias kirk
 
# Create a truststore.jsk file which holds the trusted rooted certificate
# password is: changeit
keytool -import -trustcacerts -file root-ca.pem -alias root-ca -keystore truststore.jks

NOTE: To verify the certificates you will need to add the root and signing certificate to the top of all newly generated certificates.
      You will have to do this after you generate the .p12 files otherwise you will not be able to create the correct .bundle files. 
```