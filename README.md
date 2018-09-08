# Search Guard - Security for Elasticsearch

![Logo](https://raw.githubusercontent.com/floragunncom/sg-assets/master/logo/sg_dlic_small.png) 

Search Guard(®) is an Elasticsearch plugin that offers encryption, authentication, authorization. It supports authentication via Active Directory, LDAP, Kerberos, JSON web tokens, SAML, OpenID and many more. It includes fine grained role-based access control to indices, documents and fields. Enjoy true multi tenancy in Kibana, and stay compliant with GDPR, HIPAA, PCI, SOX and ISO by using audit and compliance logging. 

Search Guard supports **OpenSSL** for maximum performance and security. The complete code is **Open Source**.

## Community Edition

Search Guard offers all basic security features for free. The Community Edition of Search Guard can be used for all projects, including commercial projects, at absolutely no cost. The Community Edition includes:

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


Please see [here for a feature comparison](https://search-guard.com/product#feature-comparison).

## Enterprise and Compliance Edition

The Enterprise Edition on Search Guard adds:

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

Please see [here for a feature comparison](https://search-guard.com/product#feature-comparison).

If you want to use our enterprise features in production, you need to obtain a license. We offer a [very flexible licensing model](https://search-guard.com/licensing/), based on productive clusters with an **unlimited number of nodes**. Non-productive systems like Development, Staging or QA are covered by the license at no additional cost.

## Trial license

You can test all enterprise modules for 60 days. A trial license is automatically created when you first install Search Guard. You do not have to install the trial license manually. Just install Search Guard and you're good to go! 

## Documentation

Please refer to the [Official documentation](http://docs.search-guard.com) for detailed information on installing and configuring Search Guard.

## Quick Start

* Install Elasticsearch

* Install the Search Guard plugin for your [Elasticsearch version](https://docs.search-guard.com/latest/search-guard-versions), e.g.:

```
<ES directory>/bin/elasticsearch-plugin install \
  -b com.floragunn:search-guard-6:6.4.0-23.0
```

* ``cd`` into ``<ES directory>/plugins/search-guard-<version>/tools``

* Execute ``./install_demo_configuration.sh``, ``chmod`` the script first if necessary. This will generate all required TLS certificates and add the Search Guard configuration to your ``elasticsearch.yml`` file. 

* Start Elasticsearch

* Test the installation by visiting ``https://localhost:9200``. When prompted, use admin/admin as username and password. This user has full access to the cluster.

* Display information about the currently logged in user by visiting ``https://localhost:9200/_searchguard/authinfo``.

* Deep dive into all Search Guard features by reading the [Search Guard documentation](http://docs.search-guard.com)

## Config hot reloading

The Search Guard configuration is stored in a dedicated index in Elasticsearch itself. Changes to the configuration are pushed to this index via the [sgadmin command line tool](https://docs.search-guard.com/latest/sgadmin). This will trigger a reload of the configuration on all nodes automatically. This has several advantages over configuration via elasticsearch.yml:

* Configuration is stored in a central place
* No configuration files on the nodes necessary
* Configuration changes do not require a restart
* Configuration changes take effect immediately

## Support
* Commercial support available through [floragunn GmbH](https://search-guard.com)
* Community support available via [google groups](https://groups.google.com/forum/#!forum/search-guard)
* Follow us on twitter [@searchguard](https://twitter.com/searchguard)

## Legal 

Search Guard is a trademark of floragunn GmbH, registered in the U.S. and in other countries.

Elasticsearch, Kibana and Logstash are trademarks of Elasticsearch BV, registered in the U.S. and in other countries. 

floragunn GmbH is not affiliated with Elasticsearch BV.
