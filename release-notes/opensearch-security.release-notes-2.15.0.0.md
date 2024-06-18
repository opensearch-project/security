## Version 2.15.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 2.15.0

### Enhancements
* Replace BouncyCastle's OpenBSDBCrypt use with password4j for password hashing and verification ([#4428](https://github.com/opensearch-project/security/pull/4428))
* Adds validation for the action groups type key ([#4411](https://github.com/opensearch-project/security/pull/4411))
* Made sensitive header log statement more clear ([#4372](https://github.com/opensearch-project/security/pull/4372))
* Refactor ActionGroup REST API test and partial fix #4166 ([#4371](https://github.com/opensearch-project/security/pull/4371))
* Support multiple audience for jwt authentication ([#4363](https://github.com/opensearch-project/security/pull/4363))
* Configure masking algorithm default ([#4345](https://github.com/opensearch-project/security/pull/4345))

### Bug Fixes
* Add cat/alias support for DNFOF ([#4440](https://github.com/opensearch-project/security/pull/4440))
* Add support for ipv6 ip address in user injection ([#4409](https://github.com/opensearch-project/security/pull/4409))
* [Fix #4280] Introduce new endpoint _plugins/_security/api/certificates ([#4355](https://github.com/opensearch-project/security/pull/4355))

### Maintenance
* Bump com.nimbusds:nimbus-jose-jwt from 9.37.3 to 9.40 ([#4337](https://github.com/opensearch-project/security/pull/4337))([#4353](https://github.com/opensearch-project/security/pull/4353))([#4396](https://github.com/opensearch-project/security/pull/4396))([#4424](https://github.com/opensearch-project/security/pull/4424))
* Bump Wandalen/wretry.action from 3.4.0 to 3.5.0 ([#4335](https://github.com/opensearch-project/security/pull/4335))
* Bump spring_version from 5.3.34 to 5.3.36 ([#4352](https://github.com/opensearch-project/security/pull/4352))([#4368](https://github.com/opensearch-project/security/pull/4368))
* Bump org.apache.camel:camel-xmlsecurity from 3.22.1 to 3.22.2 ([#4324](https://github.com/opensearch-project/security/pull/4324))
* Bump com.google.errorprone:error_prone_annotations from 2.27.0 to 2.27.1 ([#4323](https://github.com/opensearch-project/security/pull/4323))
* Bump org.checkerframework:checker-qual from 3.42.0 to 3.43.0 ([#4322](https://github.com/opensearch-project/security/pull/4322))
* Bump org.scala-lang:scala-library from 2.13.13 to 2.13.14 ([#4321](https://github.com/opensearch-project/security/pull/4321))
* Bump commons-validator:commons-validator from 1.8.0 to 1.9.0 ([#4395](https://github.com/opensearch-project/security/pull/4395))
* Bump com.netflix.nebula.ospackage from 11.9.0 to 11.9.1 ([#4394](https://github.com/opensearch-project/security/pull/4394))
* Bump com.google.errorprone:error_prone_annotations from 2.27.1 to 2.28.0 ([#4389](https://github.com/opensearch-project/security/pull/4389))
* Bump commons-cli to 1.8.0 ([#4369](https://github.com/opensearch-project/security/pull/4369))
* Fix DelegatingRestHandlerTests ([#4435](https://github.com/opensearch-project/security/pull/4435))
* Extracted the user attr handling methods from ConfigModelV7 into its own class ([#4431](https://github.com/opensearch-project/security/pull/4431))
* Bump io.dropwizard.metrics:metrics-core and org.checkerframework:checker-qual ([#4425](https://github.com/opensearch-project/security/pull/4425))
* Bump gradle to 8.7 version ([#4377](https://github.com/opensearch-project/security/pull/4377))
* Updating security reachout email ([#4333](https://github.com/opensearch-project/security/pull/4333))
* REST API tests refactoring (#4252 and #4255) ([#4328](https://github.com/opensearch-project/security/pull/4328))
* Fix flaky tests ([#4331](https://github.com/opensearch-project/security/pull/4331))
* Move REST API tests into integration tests (Part 1) ([#4153](https://github.com/opensearch-project/security/pull/4153))
* fix build errors caused by filterIndices method being moved from SnapshotUtils to IndexUtils ([#4319](https://github.com/opensearch-project/security/pull/4319))
* Extract route paths prefixes into constants ([#4358](https://github.com/opensearch-project/security/pull/4358))
