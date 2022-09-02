## Security Admin Tests

A collection of tests to perform when making changes to `securityadmin.sh`

### Running Security Admin

Details about the Security Admin tool can be found on the [OpenSearch Documentation Website](https://opensearch.org/docs/latest/security-plugin/configuration/security-admin/).

When running a cluster with the demo configuration, run the `securityadmin.sh` tool using:

```
./securityadmin.sh -cd ../../../config/opensearch-security/ -icl -nhnv \
  -cacert ../../../config/root-ca.pem \
  -cert ../../../config/kirk.pem \
  -key ../../../config/kirk-key.pem
```

### Legacy Check Tests

#### ODFE:<=0.10.0 (ES 6)

In opendistro-for-elasticsearch:0.10.0 and before (See a full list of ODFE versions [here](https://opendistro.github.io/for-elasticsearch-docs/version-history/)), opendistro-for-elasticsearch (ODFE) security was configured with the legacy Security Config v6 format. 

When running `securityadmin.sh` with the security index in the legacy v6 format, the following line will appear in the output when running the tool.

```
Legacy index '.opendistro_security' (ES 6) detected (or forced). You should migrate the configuration!
````

For information on how to migrate the security config from v6 to v7, see the [Backup, restore, and migrate](https://opensearch.org/docs/latest/security-plugin/configuration/security-admin/#backup-restore-and-migrate) section on the Security Admin Documentation page. 

#### OpenSearch and ODFE:>=1.0.0 (ES 7)

OpenSearch clusters and clusters running opendistro-for-elasticsearch:>=1.0.0 use the Security Config v7 format. When running the tool with the security index the in v7 format, the output will resemble:

```
./securityadmin.sh -cd ../../../config/opensearch-security/ -icl -nhnv \
>   -cacert ../../../config/root-ca.pem \
>   -cert ../../../config/kirk.pem \
>   -key ../../../config/kirk-key.pem
**************************************************************************
** This tool will be deprecated in the next major release of OpenSearch **
** https://github.com/opensearch-project/security/issues/1755           **
**************************************************************************
Security Admin v7
Will connect to localhost:9200 ... done
Connected as "CN=kirk,OU=client,O=client,L=test,C=de"
OpenSearch Version: 2.2.0
Contacting opensearch cluster 'opensearch' and wait for YELLOW clusterstate ...
Clustername: opensearch-cluster
Clusterstate: GREEN
Number of nodes: 2
Number of data nodes: 2
.opendistro_security index already exists, so we do not need to create one.
Populate config from /usr/share/opensearch/config/opensearch-security
Will update '/config' with ../../../config/opensearch-security/config.yml
   SUCC: Configuration for 'config' created or updated
Will update '/roles' with ../../../config/opensearch-security/roles.yml
   SUCC: Configuration for 'roles' created or updated
Will update '/rolesmapping' with ../../../config/opensearch-security/roles_mapping.yml
   SUCC: Configuration for 'rolesmapping' created or updated
Will update '/internalusers' with ../../../config/opensearch-security/internal_users.yml
   SUCC: Configuration for 'internalusers' created or updated
Will update '/actiongroups' with ../../../config/opensearch-security/action_groups.yml
   SUCC: Configuration for 'actiongroups' created or updated
Will update '/tenants' with ../../../config/opensearch-security/tenants.yml
   SUCC: Configuration for 'tenants' created or updated
Will update '/nodesdn' with ../../../config/opensearch-security/nodes_dn.yml
   SUCC: Configuration for 'nodesdn' created or updated
Will update '/whitelist' with ../../../config/opensearch-security/whitelist.yml
   SUCC: Configuration for 'whitelist' created or updated
Will update '/audit' with ../../../config/opensearch-security/audit.yml
   SUCC: Configuration for 'audit' created or updated
Will update '/allowlist' with ../../../config/opensearch-security/allowlist.yml
   SUCC: Configuration for 'allowlist' created or updated
```
