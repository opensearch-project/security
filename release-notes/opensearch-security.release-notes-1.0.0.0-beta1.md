## 2021-05-04 Version 1.0.0.0-beta1

Compatible with OpenSearch 1.0.0-beta1

### Enhancements

* Check and create multi-tenant index with alias for Update and Delete requests. Try to find a name for the multi-tenant index if index/alias with ".kibana_..._#" already exists ([#1058](https://github.com/opensearch-project/security/pull/1058))

### Bug fixes

* [Fix][Usage][Hasher] wrong file reference hash.sh ([#1093](https://github.com/opensearch-project/security/pull/1093))

### Maintenance

* Redact BCrypt security config internal hashes from audit logs ([#756](https://github.com/opensearch-project/security/pull/756))
* Update docs on snapshot restore settings ([#814](https://github.com/opensearch-project/security/pull/814))
* Optimize debug log enable check ([#895](https://github.com/opensearch-project/security/pull/895))
* Correcting setupSslOnlyMode to use AbstractSecurityUnitTest.hasCustomTransportSettings() ([#1057](https://github.com/opensearch-project/security/pull/1057))
* Remove code setting the value for cluster.routing.allocation.disk.threshold_enabled ([#1067](https://github.com/opensearch-project/security/pull/1067))
* Rename for OpenSearch ([#1126](https://github.com/opensearch-project/security/pull/1126))
* Fix CI ([#1131](https://github.com/opensearch-project/security/pull/1131))
* Consume OpenSearch 1.0.0-alpha1 ([#1132](https://github.com/opensearch-project/security/pull/1132))
* Change name and version of plugin ([#1133](https://github.com/opensearch-project/security/pull/1133))
* Build with OpenSearch 1.0.0-alpha2 ([#1140](https://github.com/opensearch-project/security/pull/1140))
* Bump plugin version to beta1 ([#1141](https://github.com/opensearch-project/security/pull/1141))
* Build security plugin with OpenSearch 1.0.0-beta1 ([#1143](https://github.com/opensearch-project/security/pull/1143))
* Change opensearch version to use ([#1146](https://github.com/opensearch-project/security/pull/1146))
* Fix echo messages and anchor links ([#1147](https://github.com/opensearch-project/security/pull/1147))
* Update static roles for compatibility for new indices used in OpenSearch Dashboards ([#1148](https://github.com/opensearch-project/security/pull/1148))
* Update release note for OpenSearch Security Plugin `1.0.0.0-beta1`([#1152](https://github.com/opensearch-project/security/pull/1152))