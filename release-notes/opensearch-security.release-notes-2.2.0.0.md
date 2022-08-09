## 2022-08-11 Version 2.2.0.0

Compatible with OpenSearch 2.2.0

### Enhancements

* Adds a basic sanity test to run against a remote cluster ([#1958](https://github.com/opensearch-project/security/pull/1958))
* Create a manually started workflow for bulk run of integration tests ([#1937](https://github.com/opensearch-project/security/pull/1937))

### Bug Fixes

* Use Collections.synchronizedSet and Collections.synchronizedMap for roles, securityRoles and attributes in User ([#1970](https://github.com/opensearch-project/security/pull/1970))

### Maintenance

* Update to Gradle 7.5 ([#1963](https://github.com/opensearch-project/security/pull/1963))
* Increment version to 2.2.0.0 ([#1948](https://github.com/opensearch-project/security/pull/1948))
* Force netty-transport-native-unix-common version ([#1945](https://github.com/opensearch-project/security/pull/1945))
* Add release notes for 2.2.0.0 release ([#1974](https://github.com/opensearch-project/security/pull/1974))
* Staging for version increment automation ([#1932](https://github.com/opensearch-project/security/pull/1932))
* Fix breaking API change introduced in Lucene 9.3.0 ([#1988](https://github.com/opensearch-project/security/pull/1988))
* Update indices resolution to be clearer ([#1999](https://github.com/opensearch-project/security/pull/1999))

### Refactoring

* Abstract waitForInit to minimize duplication and improve test reliability ([#1935](https://github.com/opensearch-project/security/pull/1935))
