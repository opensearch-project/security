## 2021-07-12 Version 1.0.0.0

Compatible with OpenSearch 1.0.0

### Enhancements

* Allow attempt to load security config in case of plugin restart even if security index already exists ([#1154](https://github.com/opensearch-project/security/pull/1154))
* Allowing granular access for data-stream related transport actions ([#1170](https://github.com/opensearch-project/security/pull/1170))
* Introducing passive_intertransport_auth to facilitate communication between nodes with adv sec enabled and nodes without adv sec enabled. ([#1156](https://github.com/opensearch-project/security/pull/1156))
* Add static action group for managing data streams ([#1258](https://github.com/opensearch-project/security/pull/1258))

### Bug fixes

* Delay the security index initial bootstrap when the index is red ([#1153](https://github.com/opensearch-project/security/pull/1153))
* Remove redundant isEmpty check and incorrect string equals operator ([#1181](https://github.com/opensearch-project/security/pull/1181))
* Do not trim SAML roles ([#1207](https://github.com/opensearch-project/security/pull/1207))
* Replace opensearch class names with opendistro class names during serialization and restore them back during deserialization ([#1278](https://github.com/opensearch-project/security/pull/1278))

### Maintenance

* Bump commons-io from 2.6 to 2.7 ([#1137](https://github.com/opensearch-project/security/pull/1137))
* Update issue template with multiple labels ([#1164](https://github.com/opensearch-project/security/pull/1164))
* move issue templates to ISSUE_TEMPLATE ([#1166](https://github.com/opensearch-project/security/pull/1166))
* Rename kibana substrings with OpenSearchDashboards in class name, method name and comments ([#1160](https://github.com/opensearch-project/security/pull/1160))
* Rename 'Open Distro' to follow open search naming convention ([#1149](https://github.com/opensearch-project/security/pull/1149))
* Build plugin on top of 1.x branch of OpenSearch core ([#1174](https://github.com/opensearch-project/security/pull/1174))
* Add build.version_qualifier and make security plugin compatible with OpenSearch 1.0.0-rc1 ([#1179](https://github.com/opensearch-project/security/pull/1179))
* Update anchor link for documentation and apply opensearch-security naming convention in PR template ([#1180](https://github.com/opensearch-project/security/pull/1180))
* Force the version of json-path 2.4.0 ([#1175](https://github.com/opensearch-project/security/pull/1175))
* Bump version to rc1, create release notes and fix the url used in release notes drafter ([#1186](https://github.com/opensearch-project/security/pull/1186))
* Rename settings constant value and related testing yml files for migration to Opensearch ([#1184](https://github.com/opensearch-project/security/pull/1184))
* Remove prefix "OPENDISTRO_" for identifier for settings ([#1185](https://github.com/opensearch-project/security/pull/1185))
* Rename documents and demo for settings ([#1188](https://github.com/opensearch-project/security/pull/1188))
* Add fallback for opendistro_security_config.ssl_dual_mode_enabled ([#1190](https://github.com/opensearch-project/security/pull/1190))
* Change security plugin REST API to support both opensearch and opendistro routes ([#1172](https://github.com/opensearch-project/security/pull/1172))
* Fix CODEOWNERS file ([#1193](https://github.com/opensearch-project/security/pull/1193))
* Dashboards rename related changes ([#1192](https://github.com/opensearch-project/security/pull/1192))
* Build OpenSearch 1.0 branch on CI ([#1189](https://github.com/opensearch-project/security/pull/1189))
* Fix install_demo_configuration.sh ([#1211](https://github.com/opensearch-project/security/pull/1211))
* Move AdvancedSecurityMigrationTests.java to opensearch directory ([#1255](https://github.com/opensearch-project/security/pull/1255))
* upgrade CXF to v3.4.3 ([#1210](https://github.com/opensearch-project/security/pull/1210))
* Bump httpclient version from 4.5.3 to 4.5.13 ([#1257](https://github.com/opensearch-project/security/pull/1257))
* Cleanup md files ([#1298](https://github.com/opensearch-project/security/pull/1298))
* Upgrade json-smart from 2.4.2 to 2.4.7 ([#1299](https://github.com/opensearch-project/security/pull/1299))
* Bump version to 1.0.0.0 and create release notes ([#1303](https://github.com/opensearch-project/security/pull/1303))
* Build on OpenSearch 1.0.0 ([#1304](https://github.com/opensearch-project/security/pull/1304))
* Consolidate the release notes for RC1 and GA ([#1305](https://github.com/opensearch-project/security/pull/1305))
