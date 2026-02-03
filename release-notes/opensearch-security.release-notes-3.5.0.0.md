## Version 3.5.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.5.0

### Features

* Allow configuring the timezone for audit log - Feature #5867 ([#5901](https://github.com/opensearch-project/security/pull/5901))
* Introduce new dynamic setting (`plugins.security.dls.write_blocked`) to block all writes when restrictions apply ([#5828](https://github.com/opensearch-project/security/pull/5828))
* JWT authentication for gRPC transport ([#5916](https://github.com/opensearch-project/security/pull/5916))
* [FEATURE] Support for HTTP/3 (server side) ([#5886](https://github.com/opensearch-project/security/pull/5886))

### Enhancements

* Enable audit logging of document contents for DELETE operations ([#5914](https://github.com/opensearch-project/security/pull/5914))
* Skip hasExplicitIndexPrivilege check for plugin users accessing their own system indices ([#5858](https://github.com/opensearch-project/security/pull/5858))
* Fix-issue-5687 allow access to nested JWT claims via dot notation ([#5891](https://github.com/opensearch-project/security/pull/5891))
* Implement buildSecureClientTransportEngine with serverName parameter ([#5894](https://github.com/opensearch-project/security/pull/5894))
* Serialize Search Request object in DLS Filter Level Handler only when… ([#5883](https://github.com/opensearch-project/security/pull/5883))

### Bug Fixes

* Bug fix: Fixing partial cache update post snapshot restore ([#5478](https://github.com/opensearch-project/security/pull/5478))
* Fix IllegalArgumentException when resolved indices are empty ([#5797](https://github.com/opensearch-project/security/pull/5797))
* Fix test failure related to change in core to add content-encoding to response headers ([#5897](https://github.com/opensearch-project/security/pull/5897))
* Fixed NPE in LDAP recursive role search ([#5861](https://github.com/opensearch-project/security/pull/5861))
* [Bugfix] Make gRPC JWT header keys case insensitive ([#5929](https://github.com/opensearch-project/security/pull/5929))

### Infrastructure

* Clear CHANGELOG post 3.4 release ([#5864](https://github.com/opensearch-project/security/pull/5864))
* Reduce log spam caused by TlsHostnameVerificationTests ([#5868](https://github.com/opensearch-project/security/pull/5868))
* New tests for protected indices feature ([#5865](https://github.com/opensearch-project/security/pull/5865))
* Removed com.carrotsearch.randomizedtesting.RandomizedRunner from tests in src/integrationTest ([#5869](https://github.com/opensearch-project/security/pull/5869))
* Removed redundant Argon2 tests to avoid memory leaks ([#5923](https://github.com/opensearch-project/security/pull/5923))

### Maintenance

* Bump at.yawk.lz4:lz4-java from 1.10.1 to 1.10.2 ([#5874](https://github.com/opensearch-project/security/pull/5874))
* Bump ch.qos.logback:logback-classic from 1.5.21 to 1.5.23 ([#5888](https://github.com/opensearch-project/security/pull/5888))
* Bump ch.qos.logback:logback-classic from 1.5.23 to 1.5.24 ([#5902](https://github.com/opensearch-project/security/pull/5902))
* Bump ch.qos.logback:logback-classic from 1.5.24 to 1.5.25 ([#5912](https://github.com/opensearch-project/security/pull/5912))
* Bump ch.qos.logback:logback-classic from 1.5.25 to 1.5.26 ([#5919](https://github.com/opensearch-project/security/pull/5919))
* Bump com.nimbusds:nimbus-jose-jwt from 10.6 to 10.7 ([#5904](https://github.com/opensearch-project/security/pull/5904))
* Bump io.dropwizard.metrics:metrics-core from 4.2.37 to 4.2.38 ([#5922](https://github.com/opensearch-project/security/pull/5922))
* Bump io.projectreactor:reactor-core from 3.8.1 to 3.8.2 ([#5910](https://github.com/opensearch-project/security/pull/5910))
* Bump net.bytebuddy:byte-buddy from 1.18.2 to 1.18.3 ([#5877](https://github.com/opensearch-project/security/pull/5877))
* Bump net.bytebuddy:byte-buddy from 1.18.3 to 1.18.4 ([#5913](https://github.com/opensearch-project/security/pull/5913))
* Bump org.checkerframework:checker-qual from 3.52.1 to 3.53.0 ([#5906](https://github.com/opensearch-project/security/pull/5906))
* Bump org.cryptacular:cryptacular from 1.2.7 to 1.3.0 ([#5921](https://github.com/opensearch-project/security/pull/5921))
* Bump org.junit.jupiter:junit-jupiter-api from 5.14.1 to 5.14.2 ([#5903](https://github.com/opensearch-project/security/pull/5903))
* Bump org.mockito:mockito-core from 5.20.0 to 5.21.0 ([#5875](https://github.com/opensearch-project/security/pull/5875))
* Bump org.ow2.asm:asm from 9.9 to 9.9.1 ([#5876](https://github.com/opensearch-project/security/pull/5876))
* Bump org.springframework.kafka:spring-kafka-test from 4.0.0 to 4.0.1 ([#5873](https://github.com/opensearch-project/security/pull/5873))
* Bump org.springframework.kafka:spring-kafka-test from 4.0.1 to 4.0.2 ([#5918](https://github.com/opensearch-project/security/pull/5918))
* Bump spring_version from 7.0.2 to 7.0.3 ([#5911](https://github.com/opensearch-project/security/pull/5911))
* Update Jackson to 2.20.1 ([#5892](https://github.com/opensearch-project/security/pull/5892))
* Upgrade eclipse dependencies ([#5863](https://github.com/opensearch-project/security/pull/5863))
* Refer to version of error_prone_annotations from core's version catalog (2.45.0) ([#5890](https://github.com/opensearch-project/security/pull/5890))
* Remove MakeJava9Happy class that's not applicable in OS 3.X ([#5896](https://github.com/opensearch-project/security/pull/5896))

### Refactoring

* Refactor plugin system index tests to use parameterized test pattern ([#5895](https://github.com/opensearch-project/security/pull/5895))