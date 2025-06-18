# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added
- Support for Argon2 hashing algorithm (#5413)
- Introduced new experimental versioned security configuration management feature ([#5357] (https://github.com/opensearch-project/security/pull/5357))


### Changed
- Underlying hasher to include new Argon2 implementation

### Dependencies
- Bump `org.eclipse.platform:org.eclipse.core.runtime` from 3.33.0 to 3.33.100 ([#5400](https://github.com/opensearch-project/security/pull/5400))
- Bump `org.eclipse.platform:org.eclipse.equinox.common` from 3.20.0 to 3.20.100 ([#5402](https://github.com/opensearch-project/security/pull/5402))
- Bump `spring_version` from 6.2.7 to 6.2.8 ([#5403](https://github.com/opensearch-project/security/pull/5403))
- Bump `stefanzweifel/git-auto-commit-action` from 5 to 6 ([#5401](https://github.com/opensearch-project/security/pull/5401))
- Bump `com.github.spotbugs` from 5.2.5 to 6.3.0 and checkstyle to 10.25.0 ([#5409](https://github.com/opensearch-project/security/pull/5409))


### Deprecated


### Removed


### Fixed


### Security

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.0...main
