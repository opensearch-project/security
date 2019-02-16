#Open Distro For Elasticsearch Security

opendistro-elasticsearch-security is an Elasticsearch plugin that offers encryption, authentication, authorization. It supports authentication via Active Directory, LDAP, Kerberos, JSON web tokens, SAML, OpenID and many more. It includes fine grained role-based access control to indices, documents and fields. Enjoy true multi tenancy in Kibana, and stay compliant with GDPR, HIPAA, PCI, SOX and ISO by using audit and compliance logging.

opendistro-elasticsearch-security supports **OpenSSL** for maximum performance and security. The complete code is **Open Source**.

## Basic features

* Full data in transit encryption
* Node-to-node encryption
* Certificate revocation lists
* Role-based cluster level access control
* Role-based index level access control
* User-, role- and permission management
* Internal user database
* HTTP basic authentication
* PKI authentication
* Proxy authentication
* User Impersonation

.

## Advance features

opendistro-elasticsearch-security-advanced-modules adds:

* Active Directory / LDAP
* Kerberos / SPNEGO
* JSON web token (JWT)
* OpenID
* SAML
* Document-level security
* Field-level security
* Audit logging 
* Compliance logging for GDPR, HIPAA, PCI, SOX and ISO compliance
* True Kibana multi-tenancy
* REST management API


## Documentation

Please refer to the [Official documentation] for detailed information on installing and configuring opendistro-elasticsearch-security plugin.

## Quick Start

* Install Elasticsearch

* Install the opendistro-elasticsearch-security plugin for your Elasticsearch version 6.5.4, e.g.:

```
<ES directory>/bin/elasticsearch-plugin install \
  -b com.amazon.opendistroforelasticsearch:elasticsearch-security:0.0.7.0
```

* ``cd`` into ``<ES directory>/plugins/opendistro_security/tools``

* Execute ``./install_demo_configuration.sh``, ``chmod`` the script first if necessary. This will generate all required TLS certificates and add the Security Plugin Configurationto your ``elasticsearch.yml`` file. 

* Start Elasticsearch

* Test the installation by visiting ``https://localhost:9200``. When prompted, use admin/admin as username and password. This user has full access to the cluster.

* Display information about the currently logged in user by visiting ``https://localhost:9200/_opendistro/_security/authinfo``.

* Deep dive into all Search Guard features by reading the [Search Guard documentation]

## Config hot reloading

The Security Plugin Configuration is stored in a dedicated index in Elasticsearch itself. Changes to the configuration are pushed to this index via the command line tool. This will trigger a reload of the configuration on all nodes automatically. This has several advantages over configuration via elasticsearch.yml:

* Configuration is stored in a central place
* No configuration files on the nodes necessary
* Configuration changes do not require a restart
* Configuration changes take effect immediately

## Support


## Legal 
Open Distro For Elasticsearch Security
Copyright 2019- Amazon.com, Inc. or its affiliates. All Rights Reserved.
