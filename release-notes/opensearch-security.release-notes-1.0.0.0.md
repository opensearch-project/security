## 2021-07-12 Version 1.0.0.0

Compatible with OpenSearch 1.0.0

### Enhancements

* Introducing passive_intertransport_auth to facilitate communication between nodes with adv sec enabled and nodes without adv sec enabled. ([#1156](https://github.com/opensearch-project/security/pull/1156))
* Add static action group for managing data streams ([#1258](https://github.com/opensearch-project/security/pull/1258))

### Bug fixes

* Do not trim SAML roles ([#1207](https://github.com/opensearch-project/security/pull/1207))
* Replace opensearch class names with opendistro class names during serialization and restore them back during deserialization ([#1278](https://github.com/opensearch-project/security/pull/1278))

### Maintenance

* Move AdvancedSecurityMigrationTests.java to opensearch directory ([#1255](https://github.com/opensearch-project/security/pull/1255))
* upgrade CXF to v3.4.3 ([#1210](https://github.com/opensearch-project/security/pull/1210))
* Bump httpclient version from 4.5.3 to 4.5.13 ([#1257](https://github.com/opensearch-project/security/pull/1257))
* Cleanup md files ([#1298](https://github.com/opensearch-project/security/pull/1298))
* Upgrade json-smart from 2.4.2 to 2.4.7 ([#1299](https://github.com/opensearch-project/security/pull/1299))
* Bump version to 1.0.0.0 and create release notes ([#1303](https://github.com/opensearch-project/security/pull/1303))
* Build on OpenSearch 1.0.0 ([#1304](https://github.com/opensearch-project/security/pull/1304))
