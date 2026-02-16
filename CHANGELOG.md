# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added

### Changed

### Features

### Enhancements
- Make security plugin aware of FIPS build param (-Pcrypto.standard=FIPS-140-3) ([#5952](https://github.com/opensearch-project/security/pull/5952))

### Bug Fixes
- Fix IllegalArgumentException when resolved indices are empty in PrivilegesEvaluator ([#5770](https://github.com/opensearch-project/security/pull/5797))
- Fixes an issue where recursive LDAP role search would fail with a NullPointerException ([#5861](https://github.com/opensearch-project/security/pull/5861))
- Serialize Search Request object in DLS Filter Level Handler only when debug mode is enabled ([#5883](https://github.com/opensearch-project/security/pull/5883))
- Skip hasExplicitIndexPrivilege check for plugin users accessing their own system indices ([#5858](https://github.com/opensearch-project/security/pull/5858))
- Fix test failure related to change in core to add content-encoding to response headers ([#5897](https://github.com/opensearch-project/security/pull/5897))
- Fix audit log writing errors for rollover-enabled alias indices ([#5878](https://github.com/opensearch-project/security/pull/5878)

- Fix the issue of unprocessed X-Request-Id ([#5954](https://github.com/opensearch-project/security/pull/5954))
### Refactoring

### Maintenance
- Bump `commons-codec:commons-codec` from 1.20.0 to 1.21.0 ([#5937](https://github.com/opensearch-project/security/pull/5937))
- Bump `at.yawk.lz4:lz4-java` from 1.10.2 to 1.10.3 ([#5938](https://github.com/opensearch-project/security/pull/5938))
- Bump `open_saml_shib_version` from 9.1.6 to 9.2.0 ([#5936](https://github.com/opensearch-project/security/pull/5936))
- Bump `com.google.googlejavaformat:google-java-format` from 1.33.0 to 1.34.1 ([#5947](https://github.com/opensearch-project/security/pull/5947))
- Bump `aws-actions/configure-aws-credentials` from 5 to 6 ([#5946](https://github.com/opensearch-project/security/pull/5946))
- Bump `ch.qos.logback:logback-classic` from 1.5.26 to 1.5.28 ([#5948](https://github.com/opensearch-project/security/pull/5948))
- Bump `com.github.seancfoley:ipaddress` from 5.5.1 to 5.6.1 ([#5949](https://github.com/opensearch-project/security/pull/5949))
- Bump `spring_version` from 7.0.3 to 7.0.4 ([#5957](https://github.com/opensearch-project/security/pull/5957))
- Bump `org.junit.jupiter:junit-jupiter-api` from 5.14.2 to 5.14.3 ([#5956](https://github.com/opensearch-project/security/pull/5956))
- Bump `org.checkerframework:checker-qual` from 3.53.0 to 3.53.1 ([#5955](https://github.com/opensearch-project/security/pull/5955))

### Removed

### Documentation

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.5...main
