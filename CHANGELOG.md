# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added

### Changed

### Features

### Enhancements

* Create a mechanism for plugins to explicitly declare actions they need to perform with their assigned PluginSubject ([#5341](https://github.com/opensearch-project/security/pull/5341))
* Moves OpenSAML jars to a Shadow Jar configuration to facilitate its use in FIPS enabled environments ([#5400](https://github.com/opensearch-project/security/pull/5404))
* Replaced the standard distribution of BouncyCastle with BC-FIPS ([#5439](https://github.com/opensearch-project/security/pull/5439))
* Introduce API Tokens with `cluster_permissions` and `index_permissions` directly associated with the token ([#5443](https://github.com/opensearch-project/security/pull/5443))
* Introduced setting `plugins.security.privileges_evaluation.precomputed_privileges.enabled` ([#5465](https://github.com/opensearch-project/security/pull/5465))
* Optimized wildcard matching runtime performance ([#5470](https://github.com/opensearch-project/security/pull/5470))
* Optimized performance for construction of internal action privileges data structure  ([#5470](https://github.com/opensearch-project/security/pull/5470))

### Bug Fixes

### Refactoring

### Maintenance
- Bump `commons-codec:commons-codec` from 1.20.0 to 1.21.0 ([#5937](https://github.com/opensearch-project/security/pull/5937))
- Bump `at.yawk.lz4:lz4-java` from 1.10.2 to 1.10.3 ([#5938](https://github.com/opensearch-project/security/pull/5938))
- Bump `open_saml_shib_version` from 9.1.6 to 9.2.0 ([#5936](https://github.com/opensearch-project/security/pull/5936))

### Removed

### Documentation

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.5...main
