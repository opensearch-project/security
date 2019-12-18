[![CI](https://github.com/opendistro-for-elasticsearch/security/workflows/CI/badge.svg?branch=master)](https://github.com/opendistro-for-elasticsearch/security/actions)

# Open Distro for Elasticsearch Security

Open Distro for Elasticsearch Security is an Elasticsearch plugin that offers encryption, authentication, and authorization. When combined with Open Distro for Elasticsearch Security-Advanced Modules, it supports authentication via Active Directory, LDAP, Kerberos, JSON web tokens, SAML, OpenID and more. It includes fine grained role-based access control to indices, documents and fields. It also provides multi-tenancy support in Kibana.

## Basic features provided by Security

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


## Advance features included in Security Advanced Modules:

* Active Directory / LDAP
* Kerberos / SPNEGO
* JSON web token (JWT)
* OpenID Connect (OIDC)
* SAML
* Document-level security
* Field-level security
* Audit logging 
* Compliance logging for GDPR, HIPAA, PCI, SOX and ISO compliance
* True Kibana multi-tenancy
* REST management API


## Documentation

Please refer to the [technical documentation](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/) for detailed information on installing and configuring opendistro-elasticsearch-security plugin.

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


## Build

* Source build instructions can be found here : 

https://github.com/opendistro-for-elasticsearch/security-parent/blob/master/README.md

## Custom CI build for testing

This project is dependent on [security-parent](https://github.com/opendistro-for-elasticsearch/security) repository and [security-advanced-modules](https://github.com/opendistro-for-elasticsearch/security-advanced-modules) repository.
By default the Github Actions CI workflow checks out the master branch of both the repos. 
In order to point to a different repository/fork/branch/tag for testing a pull request, please update `repository` and `ref` inputs of the respective checkout actions in the [ci.yml](.github/workflows/ci.yml) file. Here is a sample which uses `opendistro-1.3` branch of `security-parent` project during building.

```
    - name: Checkout security-parent
      uses: actions/checkout@v1
      with:
        repository: opendistro-for-elasticsearch/security-parent
        ref: refs/heads/opendistro-1.3
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

