# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added
- Add `plugins.security.audit.config.log4j.maximum_index_characters_per_message` setting to allow splitting of Log4j audit log messages to keep the `audit_trace_indices` and `audit_trace_resolved_indices` fields below the maximum characters specified. ([5977](https://github.com/opensearch-project/security/pull/5977))

### Changed

### Features

### Enhancements
- Make `plugins.security.dfm_empty_overrides_all` dynamically toggleable ([#6016](https://github.com/opensearch-project/security/pull/6016)
- Cache FLS status information when processing index query cache on a node ([#6044](https://github.com/opensearch-project/security/pull/6044))
- Only update internal compiled privileges configuration when the base config objects have actually changed ([#6037](https://github.com/opensearch-project/security/pull/6037))

### Bug Fixes

### Refactoring

### Maintenance
- Bump `gradle-wrapper` from 9.4.0 to 9.4.1 ([#6049](https://github.com/opensearch-project/security/pull/6049))
- Bump `1password/load-secrets-action` from 3 to 4 ([#6047](https://github.com/opensearch-project/security/pull/6047))
- Bump `io.projectreactor:reactor-core` from 3.8.2 to 3.8.4 ([#6046](https://github.com/opensearch-project/security/pull/6046))
- Bump `commons-logging:commons-logging` from 1.3.5 to 1.3.6 ([#6050](https://github.com/opensearch-project/security/pull/6050))
- Bump `org.mockito:mockito-core` from 5.21.0 to 5.23.0 ([#6048](https://github.com/opensearch-project/security/pull/6048))
- Bump `net.bytebuddy:byte-buddy` from 1.18.7 to 1.18.8 ([#6068](https://github.com/opensearch-project/security/pull/6068))
- Bump `org.scala-lang:scala3-library_3` from 3.8.2 to 3.8.3 ([#6070](https://github.com/opensearch-project/security/pull/6070))

### Removed

### Documentation

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.6...main
