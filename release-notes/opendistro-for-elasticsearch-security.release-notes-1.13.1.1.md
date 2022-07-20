## 2022-07-19 Version 1.13.1.1

Compatible with Elasticsearch 7.10.2

### Enhancement

* Allow attempt to load security config in case of plugin restart even if security index already exists ([#1154](https://github.com/opensearch-project/security/pull/1154))
* Check and create multi-tenant index with alias for Update and Delete requests. Try to find a name for the multi-tenant index if index/alias with ".kibana_..._#" already exists. ([#1058](https://github.com/opensearch-project/security/pull/1058))

### New feature

* Added changes to support validation of security roles for plugins ([#1367](https://github.com/opensearch-project/security/pull/1367)) ([#1442](https://github.com/opensearch-project/security/pull/1442))
* Add support for ResolveIndexAction handling ([#1312](https://github.com/opensearch-project/security/pull/1312)) ([#1398](https://github.com/opensearch-project/security/pull/1398))
* Introducing passive_intertransport_auth to facilitate communication between nodes with adv sec enabled and nodes without adv sec enabled.([#1156](https://github.com/opensearch-project/security/pull/1156))

### Bug fix

* fix to include hidden indices when resolving wildcards ([#1487](https://github.com/opensearch-project/security/pull/1487))
* Add validation for null elements in JSON array ([#1157](https://github.com/opensearch-project/security/pull/1157)) ([#1361](https://github.com/opensearch-project/security/pull/1361))
* Return HTTP 409 (conflict) if get parallel put request ([#1158](https://github.com/opensearch-project/security/pull/1158))
* Delay the security index initial bootstrap when the index is red ([#1153](https://github.com/opensearch-project/security/pull/1153))
* [Fix][Usage][Hasher] wrong file reference hash.sh ([#1093](https://github.com/opensearch-project/security/pull/1093))

### Test fix

* Correcting setupSslOnlyMode to use AbstractSecurityUnitTest.hasCustomTransportSettings() ([#1057](https://github.com/opensearch-project/security/pull/1057))
* Fix race condition on async test for PR [#1158](https://github.com/opensearch-project/security/pull/1158) ([#1331](https://github.com/opensearch-project/security/pull/1331))

### Maintenance

* Upgrade CXF and jackson-binding ([#1943](https://github.com/opensearch-project/security/pull/1943))
* [backport] Upgrade json-smart from 2.4.2 to 2.4.7 ([#1299](https://github.com/opensearch-project/security/pull/1299)) ([#1503](https://github.com/opensearch-project/security/pull/1503))
* [Backport] Extended role injection support for cross cluster requests ([#1195](https://github.com/opensearch-project/security/pull/1195)) ([#1441](https://github.com/opensearch-project/security/pull/1441))
* [Backport] Handled DLS/FLS/Field masking for Cross cluster replication ([#1436](https://github.com/opensearch-project/security/pull/1436))
* Added replication specific roles and system index to the configuration ([#1437](https://github.com/opensearch-project/security/pull/1437))
* Use JDK 14 for CI and CD ([#1226](https://github.com/opensearch-project/security/pull/1226))
* Redact BCrypt security config internal hashes from audit logs ([#756](https://github.com/opensearch-project/security/pull/756))
* Use smart logging and optimize debug/trace enabled checks ([#895](https://github.com/opensearch-project/security/pull/895))
* Do not trim SAML roles ([#1207](https://github.com/opensearch-project/security/pull/1207)) ([#1223](https://github.com/opensearch-project/security/pull/1223))
* Update docs on snapshot restore settings
* remove config ([#1067](https://github.com/opensearch-project/security/pull/1067))