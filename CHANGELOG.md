# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added
- [Resource Permissions] Introduces Centralized Resource Access Control Framework ([#5281](https://github.com/opensearch-project/security/pull/5281))
- Github workflow for changelog verification ([#5318](https://github.com/opensearch-project/security/pull/5318))
- Register cluster settings listener for `plugins.security.cache.ttl_minutes` ([#5324](https://github.com/opensearch-project/security/pull/5324))

### Changed
- Use extendedPlugins in integrationTest framework for sample resource plugin testing ([#5322](https://github.com/opensearch-project/security/pull/5322))

### Dependencies
- Bump `guava_version` from 33.4.6-jre to 33.4.8-jre ([#5284](https://github.com/opensearch-project/security/pull/5284))
- Bump `spring_version` from 6.2.5 to 6.2.6 ([#5283](https://github.com/opensearch-project/security/pull/5283))
- Bump `com.google.errorprone:error_prone_annotations` from 2.37.0 to 2.38.0 ([#5285](https://github.com/opensearch-project/security/pull/5285))
- Bump `org.mockito:mockito-core` from 5.15.2 to 5.17.0 ([#5296](https://github.com/opensearch-project/security/pull/5296))
- Bump `com.carrotsearch.randomizedtesting:randomizedtesting-runner` from 2.8.2 to 2.8.3 ([#5294](https://github.com/opensearch-project/security/pull/5294))
- Bump `org.ow2.asm:asm` from 9.7.1 to 9.8 ([#5293](https://github.com/opensearch-project/security/pull/5293))
- Bump `commons-codec:commons-codec` from 1.16.1 to 1.18.0 ([#5295](https://github.com/opensearch-project/security/pull/5295))
- Bump `net.bytebuddy:byte-buddy` from 1.15.11 to 1.17.5 ([#5313](https://github.com/opensearch-project/security/pull/5313))
- Bump `org.awaitility:awaitility` from 4.2.2 to 4.3.0 ([#5314](https://github.com/opensearch-project/security/pull/5314))
- Bump `org.springframework.kafka:spring-kafka-test` from 3.3.4 to 3.3.5 ([#5315](https://github.com/opensearch-project/security/pull/5315))
- Bump `com.fasterxml.jackson.core:jackson-databind` from 2.18.2 to 2.19.0 ([#5292](https://github.com/opensearch-project/security/pull/5292))
- Bump `org.apache.commons:commons-collections4` from 4.4 to 4.5.0 ([#5316](https://github.com/opensearch-project/security/pull/5316))
- Bump `com.google.googlejavaformat:google-java-format` from 1.26.0 to 1.27.0 ([#5330](https://github.com/opensearch-project/security/pull/5330))
- Bump `io.github.goooler.shadow` from 8.1.7 to 8.1.8 ([#5329](https://github.com/opensearch-project/security/pull/5329))
- Bump `commons-io:commons-io` from 2.18.0 to 2.19.0 ([#5328](https://github.com/opensearch-project/security/pull/5328))

### Deprecated

### Removed

### Fixed
- Corrections in DlsFlsFilterLeafReader regarding PointVales and object valued attributes ([#5303](https://github.com/opensearch-project/security/pull/5303))
- Fix issue computing diffs in compliance audit log when writing to security index ([#5279](https://github.com/opensearch-project/security/pull/5279))
- Fixing dependabot broken pull_request workflow for changelog update ([#5331](https://github.com/opensearch-project/security/pull/5331))
- Fixes assemble workflow failure during Jenkins build ([#5334](https://github.com/opensearch-project/security/pull/5334))
- Fixes security index stale cache issue post snapshot restore([#5307](https://github.com/opensearch-project/security/pull/5307))

### Security

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.0...main
