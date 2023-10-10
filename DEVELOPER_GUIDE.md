# Developer Guide
So you want to contribute code to this project? Excellent! We're glad you're here. Here's what you need to do.

- [Prerequisites](#prerequisites)
- [Building](#building)
- [Using IntelliJ IDEA](#using-intellij-idea)
- [Submitting Changes](#submitting-changes)

## Prerequisites
This project runs as a plugin of OpenSearch. You could [download a minimal release of OpenSearch](https://opensearch.org/downloads.html#minimal) and then install the plugin there, but at this time there are no MacOS distributions (although you can run it as a docker container, but those images come with the security plugin already preinstalled). In addition, it might come in handy to be able to always run against the latest commit of the version under development, so we'll be compiling it from source instead.

To get started, follow the [getting started section](https://github.com/opensearch-project/OpenSearch/blob/main/DEVELOPER_GUIDE.md#getting-started) of OpenSearch's developer guide. This will get OpenSearch up and running built from source code. You can skip the `./gradlew check` step to save some time. You should follow the steps until you reach the point where you can run a successful `curl localhost:9200` call. Great! now kill the server with `Ctrl+C`.

Next, inside `OpenSearch` folder run the following commands to copy the built code (snapshot) to a new folder in a different location (this where you'll be running the OpenSearch service). Here **`darwin-tar`** is an example running on MacOS, adjust `$OPENSEARCH_BUILD` path based on your version and Operating System.

```bash
export OPENSEARCH_HOME=`pwd`/opensearch-$(./gradlew properties -q | grep -E '^version:' | awk '{print $2}' | sed 's/-SNAPSHOT//g')
export OPENSEARCH_BUILD=distribution/archives/darwin-tar/build/install/opensearch-$(./gradlew properties -q | grep -E '^version:' | awk '{print $2}')
cp -Rf $OPENSEARCH_BUILD/* $OPENSEARCH_HOME
```

Let's test it!

```bash
cd $OPENSEARCH_HOME
./bin/opensearch
```

The `curl localhost:9200` call from before should also succeed now. Kill the server again with `Ctrl+c`. We are ready to install the security plugin.

>Worth noting is that the version of OpenSearch and the security plugin must match as there is an explicit version check at startup. This can be a bit confusing as, for example, at the time of this writing the `main` branch of this security plugin builds version `1.3.0.0-SNAPSHOT`, compatible with OpenSearch `1.3.0-SNAPSHOT` that gets built from branch `1.x`. Check the expected compatible version [here](https://github.com/opensearch-project/security/blob/main/plugin-descriptor.properties#L27) and make sure you get the correct branch from OpenSearch when building that project.

## Building

First create a fork of this repo and clone it locally. Changing into the directory of the newly cloned repository, run the following to build the project:

```bash
./gradlew clean assemble
```

Install the built plugin into the OpenSearch server:

```bash
export OPENSEARCH_SECURITY_HOME=$OPENSEARCH_HOME/plugins/opensearch-security
mkdir -p $OPENSEARCH_SECURITY_HOME
cp build/distributions/opensearch-security-*.zip $OPENSEARCH_SECURITY_HOME
cd $OPENSEARCH_SECURITY_HOME
unzip opensearch-security-*.zip
rm opensearch-security-*.zip
mkdir -p $OPENSEARCH_HOME/config/opensearch-security
mv config/* $OPENSEARCH_HOME/config/opensearch-security/
rm -rf config/
```

### Refreshing demo certificates

1. Use the following commands to generate new demo certificates:

```zsh
## ROOT

openssl genrsa -out root-ca-key.pem 2048
openssl req -new -x509 -sha256 -key root-ca-key.pem -subj "/DC=com/DC=example/O=Example Com Inc./OU=Example Com Inc. Root CA/CN=Example Com Inc. Root CA" -addext "basicConstraints = critical,CA:TRUE" -addext "keyUsage = critical, digitalSignature, keyCertSign, cRLSign" -addext "subjectKeyIdentifier = hash" -addext "authorityKeyIdentifier = keyid:always,issuer:always" -out root-ca.pem


## NODE

openssl genrsa -out esnode-key-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in esnode-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out esnode-key.pem
openssl req -new -key esnode-key.pem -subj "/C=de/L=test/O=node/OU=node/CN=node-0.example.com" -out esnode.csr
openssl x509 -req -in esnode.csr -out esnode.pem -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -days 3650 -extfile <(printf "subjectAltName = RID:1.2.3.4.5.5, DNS:node-0.example.com, DNS:localhost, IP:::1, IP:127.0.0.1\nkeyUsage = digitalSignature, nonRepudiation, keyEncipherment\nextendedKeyUsage = serverAuth, clientAuth\nbasicConstraints = critical,CA:FALSE")


## ADMIN

openssl req -new -newkey rsa:2048 -keyout kirk-key.pem -out kirk.csr -nodes -subj "/C=de/L=test/O=client/OU=client/CN=kirk"
openssl x509 -req -in kirk.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -out kirk.pem -days 3650 -extfile <(printf "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,nonRepudiation,keyEncipherment\nextendedKeyUsage = critical,clientAuth\nauthorityKeyIdentifier = keyid,issuer:always\nsubjectKeyIdentifier = hash")

## Remove root-ca-key.pem and other temp keys

## Generate new jks for sanity-tests which use demo certs
#### kirk-root-chain.pem is chain certificate of kirk.pem followed by root-ca.pem
openssl pkcs12 -export -in kirk-root-chain.pem -inkey kirk-key.pem -out kirk.p12 -name kirk
keytool -importkeystore -srckeystore kirk.p12 -srcstoretype PKCS12 -destkeystore kirk.jks -deststoretype JKS
```

2. Update `install_demo_configuration.sh` and `install_demo_configuration.bat` with these new certificates.
3. Add the SHA256 hashes for newly generated certs in OpenSearchSecurityPlugin.java
```zsh
cd <cert-folder>
cat <cert>.pem | sha256sum
```

### Installing demo extension users and roles

If you are working with an extension and want to set up demo users for the Hello-World extension, append following items to files inside `$OPENSEARCH_HOME/config/opensearch-security/`:
1. In **internal_users.yml**
```yaml
hw-user:
  hash: "$2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG"
  reserved: true
  description: "Demo user for ext-test"
```

2. In **roles.yml**
```yaml
extension_hw_greet:
  reserved: true
  cluster_permissions:
    - 'hw:greet'

extension_hw_full:
  reserved: true
  cluster_permissions:
    - 'hw:goodbye'
    - 'hw:greet'
    - 'hw:greet_with_adjective'
    - 'hw:greet_with_name'

legacy_hw_greet_with_name:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/hw/greet_with_name'
```

3. In **roles_mapping.yml**
```yaml
legacy_hw_greet_with_name:
  reserved: true
  users:
    - "hw-user"

extension_hw_greet:
  reserved: true
  users:
    - "hw-user"
```

To install the demo certificates and default configuration, answer `y` to the first two questions and `n` to the last one. The log should look like below:

```bash
./tools/install_demo_configuration.sh
OpenSearch Security Demo Installer
 ** Warning: Do not use on production or public reachable systems **
Install demo certificates? [y/N] y
Initialize Security Modules? [y/N] y
Cluster mode requires maybe additional setup of:
  - Virtual memory (vm.max_map_count)

Enable cluster mode? [y/N] n
Basedir: /Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT
OpenSearch install type: .tar.gz on
OpenSearch config dir: /Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT/config
OpenSearch config file: /Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT/config/opensearch.yml
OpenSearch bin dir: /Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT/bin
OpenSearch plugins dir: /Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT/plugins
OpenSearch lib dir: /Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT/lib
Detected OpenSearch Version: x-content-1.3.0-SNAPSHOT
Detected OpenSearch Security Version: *

### Success
### Execute this script now on all your nodes and then start all nodes
### OpenSearch Security will be automatically initialized.
### If you like to change the runtime configuration
### change the files in ../securityconfig and execute:
"/Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT/plugins/opensearch-security/tools/securityadmin.sh" -cd "/Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT/plugins/opensearch-security/securityconfig" -icl -key "/Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT/config/kirk-key.pem" -cert "/Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT/config/kirk.pem" -cacert "/Users/XXXXX/Test/opensearch-1.3.0-SNAPSHOT/config/root-ca.pem" -nhnv
### or run ./securityadmin_demo.sh
### To use the Security Plugin ConfigurationGUI
### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/admin.
### (Ignore the SSL certificate warning because we installed self-signed demo certificates)
```

Now if we start our server again and try the original `curl localhost:9200`, it will fail. Try this one instead: `curl -XGET https://localhost:9200 -u 'admin:admin' --insecure`. You can also make this call to return the authenticated user details:

```bash
curl -XGET https://localhost:9200/_plugins/_security/authinfo -u 'admin:admin' --insecure

{
  "user": "User [name=admin, backend_roles=[admin], requestedTenant=null]",
  "user_name": "admin",
  "user_requested_tenant": null,
  "remote_address": "[::1]:57755",
  "backend_roles": [
    "admin"
  ],
  "custom_attribute_names": [],
  "roles": [
    "own_index",
    "all_access"
  ],
  "tenants": {
    "global_tenant": true,
    "admin_tenant": true,
    "admin": true
  },
  "principal": null,
  "peer_certificates": "0",
  "sso_logout_url": null
}
```

## Using IntelliJ IDEA

Launch IntelliJ IDEA, choose **Project from Existing Sources**, and select directory with Gradle build script (`build.gradle`).

## Submitting Changes

See [CONTRIBUTING](CONTRIBUTING.md).

## Backports

The Github workflow in [`backport.yml`](.github/workflows/backport.yml) creates backport PRs automatically when the
original PR with an appropriate label `backport <backport-branch-name>` is merged to main with the backport workflow
run successfully on the PR. For example, if a PR on main needs to be backported to `1.x` branch, add a label
`backport 1.x` to the PR and make sure the backport workflow runs on the PR along with other checks. Once this PR is
merged to main, the workflow will create a backport PR to the `1.x` branch.