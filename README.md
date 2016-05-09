#Search Guard for Elasticsearch 2.3.2 **BETA 2**

2nd beta release for Search Guard 2 (compatible with Elasticsearch 2.3.2)

## Request for comments
We need your input to decide on the roadmap for SG2. If you have a minute, please help us by filling out this small survey: https://www.surveymonkey.com/r/QG23TGM

## Wiki
[Additional documentation is provided in the wiki.](https://github.com/floragunncom/search-guard/wiki)

##Roadmap
This is almost a complete rewrite of Search Guard 1 which comes with a lot of new features:

* Configuration hot reloading
* Open SSL support
* Easier to configure
 * Syntax is more easy
 * Admin CLI tool introduced (sgadmin)
 
This the 2nd beta release which is feature complete. Advanced functionalities like LDAP and Kerberos authentication/authorization as well as DLS/FLS will be available soon as separate and commercial licensed add-ons (but still Open Source). See https://github.com/floragunncom/search-guard/wiki

##Support
* Community support available via [google groups](https://groups.google.com/forum/#!forum/search-guard)
* Follow us and get community support on twitter [@searchguard](https://twitter.com/searchguard)
* Commercial support through [floragunn UG](http://floragunn.com) available soon

##Installation

* Install latest version of [search-guard-ssl plugin](https://github.com/floragunncom/search-guard-ssl)
 * ``sudo bin/plugin install com.floragunn/search-guard-ssl/2.3.2.9``

* Install search-guard-2 plugin
 * ``sudo bin/plugin install com.floragunn/search-guard-2/2.3.2.0-beta2``
 
(See also the [Vagrant file](https://github.com/floragunncom/search-guard/blob/2.2/Vagrantfile) we provide)

Both plugins need to be installed on every node in the cluster. Tribe nodes are not yet supported.

After the plugins are installed you need to configure them. ``search-guard-ssl`` needs to be configured statically
in elasticsearch.yml (any change needs a restart of the node). See [search-guard-ssl documentation](https://github.com/floragunncom/search-guard-ssl) how to configure it. ``search-guard-2`` needs only a single entry in elasticsearch.yml (see below), all other configuration is stored in Elasticsearch itself and can be dynamically changed without restarting a node or the cluster.

##Configuration

###SSL certificates
HTTP SSL is optional (but strongly recommended especially if you use HTTP Basic authentication which transmits clear text passwords). Transport SSL is mandatory and you have to generate certificates for the nodes.

There are generally two types of certificates you need to generate:

* Server/Node certificate: They need a special [Subject Alternative Name entry (san)](https://github.com/floragunncom/search-guard-ssl/blob/master/example-pki-scripts/gen_node_cert.sh) to identify
 * ``oid:1.2.3.4.5.5``
* Client certificates: Contains user DN, [see here](https://github.com/floragunncom/search-guard-ssl/blob/master/example-pki-scripts/gen_client_node_cert.sh)

###elasticsearch.yml

    security.manager.enabled: false
    searchguard.authcz.admin_dn:
      - cn=admin,ou=Test,ou=ou,dc=company,dc=com
      - cn=smith,ou=IT,ou=IT,dc=company,dc=com

``searchguard.authcz.admin_dn`` is a list of DN's which are allowed to perform administrative tasks (that is: read and write the ``searchguard`` index which holds the dynamic configuration). The client certificate (keystore) used with the sgadmin tool have to match on of the configured DN's.

###Dynamic configuration
* sg_config.yml: Configure authenticators and authorization backends
* sg_roles.yml: define the roles and the associated permissions
* sg_roles_mapping.yml: map backend roles, hosts and users to roles
* sg_internal_users.yml: user and hashed passwords (hash with hasher.sh)
* sg_action_groups.yml: group permissions together

Apply the configuration:

    plugins/search-guard-2/tools/sgadmin.sh -cd plugins/search-guard-2/sgconfig/ -ks plugins/search-guard-2/sgconfig/keystore.jks -ts plugins/search-guard-2/sgconfig/truststore.jks  -nhnv

Generate hashed passwords for sg_internal_users.yml:

    plugins/search-guard-2/tools/hasher.sh -p mycleartextpassword

All this files are stored as documents in Elasticsearch within the ``searchguard`` index.
This index is specially secured so that only a admin user with a special SSL certificate may write or read this index. Thats the reason why you need the sgadmin tool to update the configuration (that is loading the files into ES). 

After one or more files are updated Search Guard will automatically reconfigure and the changes will take effect almost immediately. No need to restart ES nodes and deal with config files on the servers. The sgadmin tool can also be used fom a desktop machine as long ES servers are reachable through 9300 port (transport protocol).

##How does it work
Search Guard is build upon search-guard-ssl, a plugin which enables and enforce transport protocol (node-to-node) encryption and mutual SSL authentication. This makes sure that only trusted nodes can join the cluster. If a client connects (either through HTTP/REST or TransportClient) the request will be associated with the authenticated user. The client have therefore to authenticate either via HTTP (only BASIC supported currently) or via PKI (mutual SSL) when connecting with the transport client. 

###Config hot reloading
All configuration is held in Elasticsearch itself and if if the configuration is updated (through sgadmin) then all nodes will be informed about the update and will reload the configuration. This has several advantages over configuration via elasticsearch.yml

* Configuration is held in a central place and therefore automatically identical for all nodes
* Easy update, no dealing with files on different servers
* Configuration change will not need node restarts


