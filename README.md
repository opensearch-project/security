# Search Guard - Security for Elasticsearch

![Logo](https://raw.githubusercontent.com/floragunncom/sg-assets/master/logo/sg_dlic_small.png) 

Search Guard(®) is an Elasticsearch plugin that offers encryption, authentication, and authorization. It builds on Search Guard SSL and provides pluggable authentication and authorization modules in addition. Search Guard is fully compatible with Kibana, Logstash and Beats.

As an alternative to other security solutions for Elasticsearch, Search Guard offers the following main features:

* TLS on transport- and REST-layer
* Fine-grained role- and index-based access control
* HTTP Basic Authentication
* LDAP / Active Directory
* Kerberos / SPNEGO
* JSON web token
* Document- and Field-level security
* Audit logging
* Kibana multi-tenancy
* REST management API
* Proxy support
* User impersonation

Search Guard supports **OpenSSL** for maximum performance and security. The complete code is **Open Source**.

## Quick Start

* Install Elasticsearch

* Install the Search Guard plugin for your [Elasticsearch version](https://github.com/floragunncom/search-guard/wiki), e.g.:

```
<ES directory>/bin/elasticsearch-plugin install \
  -b com.floragunn:search-guard-5:5.4.0-12
```

* ``cd`` into ``<ES directory>/plugins/search-guard-<version>/tools``

* Execute ``./install_demo_configuration.sh``, ``chmod`` the script first if necessary. This will generate all required TLS certificates and add the Search Guard configuration to your ``elasticsearch.yml`` file. 

* Start Elasticsearch

* Execute ``./sgadmin_demo.sh``, ``chmod`` the script if necessary first. This will execute ``sgadmin`` and populate the Search Guard configuration index with the files contained in the ``plugins/search-guard-<version>/sgconfig`` directory.

* Test the installation by visiting ``https://localhost:9200``. When prompted, use admin/admin as username and password. This user has full access to the cluster.

* Display information about the currently logged in user by visiting ``https://localhost:9200/_searchguard/authinfo``.

* Deep dive into all Search Guard features by reading the [Search Guard documentation](http://floragunncom.github.io/search-guard-docs/)

If you want to play around with different configuration settings, you can change the files in the ``sgconfig`` directory directly. After that, just execute ``./sgadmin_demo.sh`` again for the changes to take effect. 

* sg\_config.yml: Configure authenticators and authorization backends
* sg\_internal\_users.yml: user and hashed passwords (hash with hasher.sh)
* sg\_roles\_mapping.yml: map backend roles, hosts and users to roles
* sg\_action\_groups.yml: define permission groups
* sg\_roles.yml: define the roles and the associated permissions

Please refer to the official [Search Guard documentation](http://floragunncom.github.io/search-guard-docs/) for a complete guide.

### Search Guard Bundle
As an alternative, you can also download the [Search Guard Bundle](https://github.com/floragunncom/search-guard/wiki/Search-Guard-Bundle). This is an Elasticsearch installation, pre-installed and pre-configured with Search Guard. It contains all enterprise features and templates for all configuration files. Just download, unzip and run! 

## Documentation

The [Official Search Guard documentation](http://floragunncom.github.io/search-guard-docs/) is available on GitHub.

## Commercial use

Search Guard offers all basic security features for free. If you want to use our enterprise features for commercial projects, you need to obtain a license. We offer a [very flexible licensing model](https://floragunn.com/searchguard/searchguard-license-support/), based on productive clusters, not the number of nodes. Scale your cluster, not your cost! Non-productive systems like Development, Staging or QA are included in the license as well.

## Enterprise modules trial

You can test all enterprise modules for as long as you like, a trial license key is not required. Please refer to the chapter "Installing enterprise modules" from the [Official Search Guard documentation](https://github.com/floragunncom/search-guard-docs/blob/master/installation.md) for installation instructions.

## Architecture

![Architecture](https://github.com/floragunncom/sg-assets/raw/master/diagrams/SG_Architecture_Overview.png)


## Config hot reloading

The Search Guard configuration is stored in a dedicated index in Elasticsearch itself. Changes to the configuration are pushed to this index via the [sgadmin command line tool](https://github.com/floragunncom/search-guard-docs/blob/master/sgadmin.md). This will trigger a reload of the configuration on all nodes automatically. This has several advantages over configuration via elasticsearch.yml:

* Configuration is stored in a central place
* No configuration files on the nodes necessary
* Configuration changes do not require a restart
* Configuration changes take effect immediately

## Support
* Commercial support available through [floragunn GmbH](https://floragunn.com/searchguard/searchguard-license-support/)
* Community support available via [google groups](https://groups.google.com/forum/#!forum/search-guard)
* Follow us and get community support on twitter [@searchguard](https://twitter.com/searchguard)

## License

```
This software is licensed under the Apache License, version 2 ("ALv2"), quoted below.

Copyright 2015-2017 floragunn GmbH 
https://floragunn.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Legal 

Search Guard is an independent implementation of a security access layer for Elasticsearch. Search Guard is completely independent from Elasticsearch own security offerings. floragunn GmbH is not affiliated with Elasticsearch BV.

Search Guard is a trademark of floragunn GmbH, registered in the U.S. and in other countries.

Elasticsearch, Kibana and Logstash are trademarks of Elasticsearch BV, registered in the U.S. and in other countries. 
