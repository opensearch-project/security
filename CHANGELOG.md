# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added

### Changed

### Features

### Enh
- Make security plugin aware of FIPS build param (-Pcrypto.standard=FIPS-140-3) ([#5952](https://github.com/opensearch-project/security/pull/5952))
- Hardens input validation for resource sharing APIs ([#5831](https://github.com/opensearch-project/security/pull/5831)

* Create a mechanism for plugins to explicitly declare actions they need to perform with their assigned PluginSubject ([#5341](https://github.com/opensearch-project/security/pull/5341))
* Moves OpenSAML jars to a Shadow Jar configuration to facilitate its use in FIPS enabled environments ([#5400](https://github.com/opensearch-project/security/pull/5404))
* Replaced the standard distribution of BouncyCastle with BC-FIPS ([#5439](https://github.com/opensearch-project/security/pull/5439))
* Introduce API Tokens with `cluster_permissions` and `index_permissions` directly associated with the token ([#5443](https://github.com/opensearch-project/security/pull/5443))
* Introduced setting `plugins.security.privileges_evaluation.precomputed_privileges.enabled` ([#5465](https://github.com/opensearch-project/security/pull/5465))
* Optimized wildcard matching runtime performance ([#5470](https://github.com/opensearch-project/security/pull/5470))
* Optimized performance for construction of internal action privileges data structure  ([#5470](https://github.com/opensearch-project/security/pull/5470))

### Bug Fixes
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
- Bump `spring_version` from 7.0.3 to 7.0.5 ([#5957](https://github.com/opensearch-project/security/pull/5957), [#5967](https://github.com/opensearch-project/security/pull/5967))
- Bump `org.junit.jupiter:junit-jupiter-api` from 5.14.2 to 5.14.3 ([#5956](https://github.com/opensearch-project/security/pull/5956))
- Bump `org.checkerframework:checker-qual` from 3.53.0 to 3.53.1 ([#5955](https://github.com/opensearch-project/security/pull/5955))
- Bump `open_saml_version` from 5.1.6 to 5.2.1 ([#5965](https://github.com/opensearch-project/security/pull/5965))

### Removed

### Documentation

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.5...main
