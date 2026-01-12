# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added

### Changed

### Features

### Enhancements
- Introduce new dynamic setting (plugins.security.dls.write_blocked) to block all writes when restrictions apply ([#5828](https://github.com/opensearch-project/security/pull/5828))

- Support nested JWT claims in role DLS queries ([#5687](https://github.com/opensearch-project/security/issues/5687))
- Support creation of client SSL engine with a given SNI ([#5894](https://github.com/opensearch-project/security/pull/5894))

### Bug Fixes
- Fix IllegalArgumentException when resolved indices are empty in PrivilegesEvaluator ([#5770](https://github.com/opensearch-project/security/pull/5797))
- Fixes an issue where recursive LDAP role search would fail with a NullPointerException ([#5861](https://github.com/opensearch-project/security/pull/5861))
- Serialize Search Request object in DLS Filter Level Handler only when debug mode is enabled ([#5883](https://github.com/opensearch-project/security/pull/5883))
- Skip hasExplicitIndexPrivilege check for plugin users accessing their own system indices ([#5858](https://github.com/opensearch-project/security/pull/5858))
- Fix test failure related to change in core to add content-encoding to response headers ([#5897](https://github.com/opensearch-project/security/pull/5897))

### Refactoring

### Maintenance
- Bump `spring_version` from 7.0.1 to 7.0.2 ([#5852](https://github.com/opensearch-project/security/pull/5852))
- Bump `org.apache.commons:commons-text` from 1.14.0 to 1.15.0 ([#5857](https://github.com/opensearch-project/security/pull/5857))
- Bump `org.eclipse.platform:org.eclipse.core.runtime` from 3.34.0 to 3.34.100 and `org.eclipse.platform:org.eclipse.equinox.common` from 3.20.200 to 3.20.300 ([#5863](https://github.com/opensearch-project/security/pull/5863))
- Bump `at.yawk.lz4:lz4-java` from 1.10.1 to 1.10.2 ([#5874](https://github.com/opensearch-project/security/pull/5874))
- Bump `org.springframework.kafka:spring-kafka-test` from 4.0.0 to 4.0.1 ([#5873](https://github.com/opensearch-project/security/pull/5873))
- Bump `net.bytebuddy:byte-buddy` from 1.18.2 to 1.18.3 ([#5877](https://github.com/opensearch-project/security/pull/5877))
- Bump `org.mockito:mockito-core` from 5.20.0 to 5.21.0 ([#5875](https://github.com/opensearch-project/security/pull/5875))
- Bump `org.ow2.asm:asm` from 9.9 to 9.9.1 ([#5876](https://github.com/opensearch-project/security/pull/5876))
- Refer to version of error_prone_annotations from core's version catalog (2.45.0) ([#5890](https://github.com/opensearch-project/security/pull/5890))
- Bump `ch.qos.logback:logback-classic` from 1.5.21 to 1.5.24 ([#5888](https://github.com/opensearch-project/security/pull/5888), [#5902](https://github.com/opensearch-project/security/pull/5902))
- Bump `jackson` from 2.18.1 to 2.20.1 ([#5892](https://github.com/opensearch-project/security/pull/5892))

### Removed
- Remove MakeJava9Happy class that's not applicable in OS 3.X ([#5896](https://github.com/opensearch-project/security/pull/5896))

### Documentation

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.4...main
