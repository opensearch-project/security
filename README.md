[![CI](https://github.com/opendistro-for-elasticsearch/security/workflows/CI/badge.svg?branch=master)](https://github.com/opendistro-for-elasticsearch/security/actions)
[![codecov](https://codecov.io/gh/opendistro-for-elasticsearch/security/branch/master/graph/badge.svg)](https://codecov.io/gh/opendistro-for-elasticsearch/security)

# Open Distro for Elasticsearch Security

Open Distro for Elasticsearch Security is an Elasticsearch plugin that offers encryption, authentication, and authorization. When combined with Open Distro for Elasticsearch Security-Advanced Modules, it supports authentication via Active Directory, LDAP, Kerberos, JSON web tokens, SAML, OpenID and more. It includes fine grained role-based access control to indices, documents and fields. It also provides multi-tenancy support in Kibana.

## Features provided by Security

### Encryption:

* Full data in transit encryption
* Node-to-node encryption
* Certificate revocation lists
* Hot Certificate renewal 

### Authentication: 
* Internal user database
* HTTP basic authentication
* PKI authentication
* Proxy authentication
* User Impersonation
* Active Directory / LDAP
* Kerberos / SPNEGO
* JSON web token (JWT)
* OpenID Connect (OIDC)
* SAML

### Access control:
* Role-based cluster level access control
* Role-based index level access control
* User-, role- and permission management
* Document-level security
* Field-level security
* REST management API

### Audit/Compliance logging:
* Audit logging 
* Compliance logging for GDPR, HIPAA, PCI, SOX and ISO compliance

### Kibana multi-tenancy
* True Kibana multi-tenancy



## Documentation

Please refer to the [technical documentation](https://opendistro.github.io/for-elasticsearch-docs/docs/security/configuration/) for detailed information on installing and configuring opendistro-elasticsearch-security plugin.

## Quick Start

* Install Elasticsearch

* Install the opendistro-elasticsearch-security plugin for your Elasticsearch version 6.5.4, e.g.:

```
<ES directory>/bin/elasticsearch-plugin install \
  -b com.amazon.opendistroforelasticsearch:opendistro_security:0.8.0.0
```

* ``cd`` into ``<ES directory>/plugins/opendistro_security/tools``

* Execute ``./install_demo_configuration.sh``, ``chmod`` the script first if necessary. This will generate all required TLS certificates and add the Security Plugin Configuration to your ``elasticsearch.yml`` file. 

* Start Elasticsearch

* Test the installation by visiting ``https://localhost:9200``. When prompted, use admin/admin as username and password. This user has full access to the cluster.

* Display information about the currently logged in user by visiting ``https://localhost:9200/_opendistro/_security/authinfo``.


## Test and Build

* Run all tests

```
mvn clean test
```

* Build artifacts (zip, deb, rpm)

```
mvn clean package -Padvanced -DskipTests
artifact_zip=`ls $(pwd)/target/releases/opendistro_security-*.zip | grep -v admin-standalone`
./gradlew build buildDeb buildRpm --no-daemon -ParchivePath=$artifact_zip -Dbuild.snapshot=false
```


## Config hot reloading

The Security Plugin Configuration is stored in a dedicated index in Elasticsearch itself. Changes to the configuration are pushed to this index via the command line tool. This will trigger a reload of the configuration on all nodes automatically. This has several advantages over configuration via elasticsearch.yml:

* Configuration is stored in a central place
* No configuration files on the nodes necessary
* Configuration changes do not require a restart
* Configuration changes take effect immediately


## License

This code is licensed under the Apache 2.0 License. 

## Copyright

Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

