# Search Guard Security Plugin for ES 1.x
Elasticsearch security for free.

##Search Guard for Elasticsearch 2 is coming in Feb. 2016

Search Guard is a free and open source plugin for Elasticsearch which provides security features. Currently only Elasticsearch 1.5, 1.6 and 1.7 is supported, Search Guard for Elasticsearch 2 is coming in Feb. 2016.
Second alpha version for [Search Guard 2 is available here](https://github.com/floragunncom/search-guard/tree/2.2) 

If you need "only" SSL for Elasticsearch 2 have a look here: https://github.com/floragunncom/search-guard-ssl

![Logo](https://raw.githubusercontent.com/floragunncom/sg-assets/master/logo/sg_logo_small.jpg) 


[![Build Status](https://travis-ci.org/floragunncom/search-guard.svg?branch=master)](https://travis-ci.org/floragunncom/search-guard) [![Coverage Status](https://coveralls.io/repos/floragunncom/search-guard/badge.svg?branch=master)](https://coveralls.io/r/floragunncom/search-guard?branch=master)

##Other Versions
* ES 2.2 https://github.com/floragunncom/search-guard/tree/2.2
* ES 1.5 https://github.com/floragunncom/search-guard/tree/es1.5
* ES 1.6 https://github.com/floragunncom/search-guard/tree/es1.6
* ES 1.7 https://github.com/floragunncom/search-guard/tree/es1.7
* ES 1.x https://github.com/floragunncom/search-guard/tree/master


##Support
* Community support available via [google groups](https://groups.google.com/forum/#!forum/search-guard)
* Commercial support through [floragunn UG](http://floragunn.com) available Februar 2016

##Features
* Flexible REST layer access control (User/Role based; on aliases, indices and types)
* Flexible transport layer access control (User/Role based; on aliases, indices and types)
* Document level security (DLS): Retrieve only documents matching criterias
* Field level security (FLS): Filter out fields/sourceparts from a search response
* HTTP authentication (Basic, Proxy header, SPNEGO/Kerberos, Mutual SSL/CLIENT-CERT)
* HTTP session support through cookies
* Flexible authentication backends (LDAP(s)/Active Directory, File based, Proxy header, Native Windows through WAFFLE) 
* Flexible authorization backends (LDAP(s)/Active Directory, File based, Native Windows through WAFFLE) 
* Node-to-node encryption through SSL/TLS (Transport layer)
* Secure REST layer through HTTPS (SSL/TLS)
* X-Forwarded-For (XFF) support
* Audit logging
* Anonymous login/unauthenticated access
* Works with Kibana 4 and logstash

##Limitations
* When using DLS or FLS you can still search in all documents/fields but not all documents/fields are returned
* Transport layer access control only with simple username/password login
* No automatic multi index filters (see below)
* Currently monitoring of the cluster needs no authentication and is allowed always (this may change in the future)

##How it works
Basically Search Guard consists of an authentication, authorization, SSL/TLS, XFF, HTTP session and audit log module and access control. All of them without the exception of access control are more or less self-explanatory. But access control, the heart of Search Guard, needs some more attention.

Search Guard has the concept of routing a request through a chain of filters which can modify or block the request/response. There are currently 3 types of filters:

* **actionrequest/restrequest filter**: Checks if the user is allowed to perform actions (like read, write, admin actions …). Works generally, not only for search requests.
* **dls filter**: filters out documents from the search response
* **fls filter**: filter out fields from the documents of a search response

##Pre-Installation
###Check Release Integrity

You **must** verify the integrity of the downloaded files. We provide PGP signatures for every release file. This signature should be matched against the KEYS file. We also provide MD5 and SHA-1 checksums for every release file. After you download the file, you should calculate a checksum for your download, and make sure it is the same as ours. [Here](http://www.openoffice.org/download/checksums.html) and [here](https://www.apache.org/info/verification.html) are some tips how to verify the pgp signatures.

###Setup ACL rules

It's recommended to setup the access control rules (ACL rules) **before** installing the plugin to simplify the installation process.
If you install the plugin first you have to do extra effort cause then your're firstly locked-out of elasticsearch.

Why not install a ACL rules file which grants _all access_ for a user with role _admin_?

```javascript
curl -XPUT 'http://localhost:9200/searchguard/ac/ac' -d '{
    "acl": [
    {    
        "__Comment__": "By default no filters are executed and no filters a by-passed. In such a case an exception is thrown and access will be denied.",
        "filters_bypass": [],
        "filters_execute": []
     },
     {
           "__Comment__": "For role *admin* all filters are bypassed (so none will be executed). This means unrestricted access.",
           "roles": [
               "admin"
           ],
           "filters_bypass": ["*"],
           "filters_execute": []
     }
     ]
}'
```
     
##Installation
Install it like any other Elasticsearch plugin

``bin/plugin -i com.floragunn/search-guard/0.5``

Prerequisites:

* Java 7 or 8 (recommended)
* Elasticsearch 1.5.x

Build it yourself:
* Install maven 3.1+
* ``git clone https://github.com/floragunncom/search-guard.git`
* ``cd search-guard``
* execute ``mvn package -DskipTests`` 


##Configuration

###Logging
Configured in elasticsearch's logging.yml. Nothing special. To enable debug just add

``logger.com.floragunn: DEBUG``


###Keys
Two kind of keys are used by Search Guard:
* Search Guard node key (searchguard_node.key)
 * This is a key which generated and saved to disk by the plugin if a node starts up (and key is not already present)
 * Its used to secure node communication even if no SSL/TLS is configured
 * Every node in the cluster has to use the same key file (searchguard_node.key)
 * It's recommended to let one node generate a file and copy this (securely) to every node in the cluster  
* Optionally SSL keys (certificates)
 * If you want to use SSL/TLS see [example-pki-scripts](example-pki-scripts) how to generate the certificates. It's strongly recommended to use a root certificate.</a>
 * See https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores
 * or https://tomcat.apache.org/tomcat-8.0-doc/ssl-howto.html

###ACL rules (stored in Elasticsearch itself)
The security rules for each module are stored in an special index ``searchguard`` and with a type and id of ``ac``.

See below (or look at chapter **Pre-Installation**) for more details.

###AuthN & AuthZ in elasticsearch.yml
See [searchguard_config_template.yml](searchguard_config_template.yml). Just copy the content over to elasticsearch.yml and modify the settings so fit your needs. A very basic example you can find [here](searchguard_config_example_1.yml)

####Within elasticsearch.yml you configure

* Global options for searchguard
* HTTP/REST SSL/TLS
* Transport SSL/TLS
* HTTP authentication method
 * Basic, SPNEGO, Client-Cert, Proxy header, WAFFLE (NTLM), ...
* Authentication backend
 * LDAP, File based, Always authenticate
* Authorization backend
 * LDAP, WAFFLE (AD), File based
* Security Filters (see next section)

####Security Filters
All the configuration up to know makes only sense if we can limit the usage of Elasticsearch for the authenticated user.
There are four types of security filters (by now) which also can be used together.

* **restactionfilter**: Limit Elasticsearch actions by type of rest actions which are allowed (or forbidden)
* **actionrequestfilter**: Limit Elasticsearch actions by type request actions which are allowed (or forbidden)
* **dlsfilter**: Only return documents which match defined criterias
* **flsfilter**: Filter document source and exclude (or include) fields

You have to configure at least on filter.

###On which nodes the plugin needs to be installed
If you use either transport layer SSL or DLS or FLS you have to install it on every node. Otherwise install it on every client node which is exposed to be the entry point into the cluster and on every node which exposes the HTTP REST API. Please note that the ``searchguard.config_index_name`` must be the same for all nodes in within a cluster.

###Update and Upgrade
TBD

##Auditlog
Auditlog is stored in Elasticsearch within the _searchguard_ index (with type _audit_)<br>
``curl -XGET 'http://localhost:9200/searchguard/audit/_search?pretty=true'``

##Rules evaluation 
Now lets define for which user on which index which filter have to be applied.
```javascript
{
    "acl": [
    {    
        "__Comment__": "By default no filters are executed and no filters a by-passed. In such a case a exception is throws an access will be denied.",
        "filters_bypass": [],
        "filters_execute": []
     },
       {
           "__Comment__": "For admin role all filters are bypassed (so none will be executed) for all indices. This means unrestricted access at all for this role.",
           "roles": [
               "admin"
           ],
           "filters_bypass": ["*"],
           "filters_execute": []
       },
       {
           "__Comment__": "For every authenticated user who access the index 'public' for this access all non dls and all non fls filters are executed.",
           "indices": [
               "public"
           ],
           "filters_bypass": ["dlsfilter.*","dlsfilter.*"],
           "filters_execute": ["*"]
       },
       {
       "__Comment__": "For marketing role all filters are bypassed (so none will be executed) for index 'marketing'. This means unrestricted access to this index for this role.",
        "roles": ["marketing"],
        "indices": [
               "marketing"
           ],
           "filters_bypass": ["*"],
           "filters_execute": []
       },
       {
        "__Comment__": "For finance role all filters are bypassed (so none will be executed) for index 'finance'. This means unrestricted access to this index for this role.",
        "roles": ["finance"],
        "indices": [
               "financ*"
           ],
           "filters_bypass": ["*"],
           "filters_execute": []
       },
       {
       "__Comment__": "For marketing role the filters 'flsfilter.filter_sensitive_finance' and 'actionrequestfilter.readonly' are executed (but no other filters) for index 'finance'",
        "roles": ["marketing"],
        "indices": [
               "financ*"
           ],
           "filters_bypass": [],
           "filters_execute": ["flsfilter.filter_sensitive_fina*","actionrequestfilter.readonly"]
       },
       {
           "__Comment__": "For roles 'ceo' 'marketing' 'finance' all filters are bypassed (so none will be executed) for alias 'planning'. This means unrestricted access to this alias for this roles.",
           "roles": [
               "ce*o","marke*ing","*nanc*"
           ],
           "aliases": [
               "planning"
           ],
           "filters_bypass": ["*"],
           "filters_execute": []
       },
       {
           "__Comment__": "For finance role the filters 'dlsfilter.filter_sensite_from_ceodata' and 'actionrequestfilter.readonly' are executed (but no other filters) for index 'ceodata'",
           "roles": [
               "finance"
           ],
           "indices": [
               "ceodat*"
           ],
           "filters_bypass": [],
           "filters_execute": ["dlsfilter.filter_sensitive_from_ceodata", "actionrequestfilter.readonly"]
       },
       {
           "__Comment__": "For role 'ceo' all filters are bypassed (so none will be executed) for index 'ceodata'. This means unrestricted access to this index for this role.",
           "roles": [
               "ce*o"
           ],
           "indices": [
               "ceodata"
           ],
           "filters_bypass": ["*"],
           "filters_execute": []
       }
   ]
} 
```

For every rule that match all execute and bypass filters will be concatenated, and **bypass** is winning over **execute**.
For example if an user which has the roles _marketing_ and _finance_ and want to access index _marketing_ the final result looks like 

```javascript
filters_bypass= ["*"],
filters_execute=["flsfilter.filter_sensitive_fina*","actionrequestfilter.readonly"]
```
which then will be resolved to ``filters_bypass= ["*"]`` (execute **NO** filter at all).
Because bypass is winning.


If a user which has the _marketing_ role and want to access index _finance_ the final result looks like 

```javascript
filters_bypass=[],
filters_execute=["flsfilter.filter_sensitive_fina*","actionrequestfilter.readonly"]
```
which then will be resolved to ``filters_execute=["flsfilter.filter_sensitive_fina*","actionrequestfilter.readonly"]`` (execute these two filters, no others).

For an admin accessing index _public_ it looks like

```javascript
filters_bypass=["*","dls.*","fls.*"],
filters_execute=["*"]
```

which then will be resolved to ``filters_bypass= ["*"]`` (execute **NO** filter at all).
Because bypass is winning.

If filters resolve to

```javascript
  filters_bypass= []
  filters_execute= []
```
then an security exception will be thrown.



For the sake of completeness a rule definition can look like:
```javascript
{
        //who is the requestor
        "hosts":[
           "10.*.1.*","host-*.company.org"
        ],
        "users":[
           "*"
        ],
        "roles":[
           "*"
        ],

        //on what resources do the requestor operate
        "indices":[
           "public"
        ],
        "aliases":[
           "..."
        ],

        //which filters have to be applied or can be bypassed for this 
        //requestor on this resource
        "filters_bypass": ["*"],
        "filters_execute": []
}
```
Everywhere a simple wildcard (*) can be used.

To make the rule apply all present attributes (users, roles, hosts, indices, aliases) must match. An attribute which is missing or is empty does always match. An attribute only containing the wildcard sign (*) does also match always.

### No automatic multi index filters
If you access more than one index (e.g. search in multiple indices) only rules will match when they list all the indices (or "*”). So for a multi index search on the indices _marketing_ and _finance_ a rules have to look like: 

```javascript
{       
    "roles": [...],
    "indices": [
         "finance","marketing"
    ],
    "filters_bypass": [...],
    "filters_execute": [...]
}
```
You can circumvent this by using aliases.

###License
Copyright 2015 floragunn UG (haftungsbeschränkt)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   ``http://www.apache.org/licenses/LICENSE-2.0``

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
