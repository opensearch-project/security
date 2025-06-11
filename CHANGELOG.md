# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added
- [Resource Permissions] Introduces Centralized Resource Access Control Framework ([#5281](https://github.com/opensearch-project/security/pull/5281))
- Github workflow for changelog verification ([#5318](https://github.com/opensearch-project/security/pull/5318))
- Register cluster settings listener for `plugins.security.cache.ttl_minutes` ([#5324](https://github.com/opensearch-project/security/pull/5324))
- Add flush cache endpoint for individual user ([#5337](https://github.com/opensearch-project/security/pull/5337))
- Handle roles in nested claim for JWT auth backends ([#5355](https://github.com/opensearch-project/security/pull/5355))
- Integrate search-relevance functionalities with security plugin ([#5376](https://github.com/opensearch-project/security/pull/5376))
- Add forecast roles and permissions ([#5386](https://github.com/opensearch-project/security/pull/5386))
- Create a mechanism for plugins to explicitly declare actions they need to perform with their assigned PluginSubject ([#5341](https://github.com/opensearch-project/security/pull/5341))

### Changed
- Use extendedPlugins in integrationTest framework for sample resource plugin testing ([#5322](https://github.com/opensearch-project/security/pull/5322))
- [Resource Sharing] Refactor ResourcePermissions to refer to action groups as access levels ([#5335](https://github.com/opensearch-project/security/pull/5335))
- Introduced new, performance-optimized implementation for tenant privileges ([#5339](https://github.com/opensearch-project/security/pull/5339))
- Performance improvements: Immutable user object ([#5212](https://github.com/opensearch-project/security/pull/5212))
- Include mapped roles when setting userInfo in ThreadContext ([#5369](https://github.com/opensearch-project/security/pull/5369))
- Adds details for debugging Security not initialized error([#5370](https://github.com/opensearch-project/security/pull/5370))
- [Resource Sharing] Store resource sharing info in indices that map 1-to-1 with resource index ([#5358](https://github.com/opensearch-project/security/pull/5358))

### Dependencies
- Bump `guava_version` from 33.4.6-jre to 33.4.8-jre ([#5284](https://github.com/opensearch-project/security/pull/5284))
- Bump `spring_version` from 6.2.5 to 6.2.7 ([#5283](https://github.com/opensearch-project/security/pull/5283), [#5345](https://github.com/opensearch-project/security/pull/5345))
- Bump `com.google.errorprone:error_prone_annotations` from 2.37.0 to 2.38.0 ([#5285](https://github.com/opensearch-project/security/pull/5285))
- Bump `org.mockito:mockito-core` from 5.15.2 to 5.18.0 ([#5296](https://github.com/opensearch-project/security/pull/5296), [#5362](https://github.com/opensearch-project/security/pull/5362))
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
- Upgrade kafka_version from 3.7.1 to 4.0.0 ([#5131](https://github.com/opensearch-project/security/pull/5131))
- Bump `io.dropwizard.metrics:metrics-core` from 4.2.30 to 4.2.32 ([#5361](https://github.com/opensearch-project/security/pull/5361))
- Bump `org.junit.jupiter:junit-jupiter` from 5.12.2 to 5.13.1 ([#5371](https://github.com/opensearch-project/security/pull/5371), [#5382](https://github.com/opensearch-project/security/pull/5382))
- Bump `bouncycastle_version` from 1.80 to 1.81 ([#5380](https://github.com/opensearch-project/security/pull/5380))
- Bump `org.junit.jupiter:junit-jupiter-api` from 5.13.0 to 5.13.1 ([#5383](https://github.com/opensearch-project/security/pull/5383))
- Bump `org.checkerframework:checker-qual` from 3.49.3 to 3.49.4 ([#5381](https://github.com/opensearch-project/security/pull/5381))

### Deprecated

### Removed

- Removed unused support for custom User object serialization ([#5339](https://github.com/opensearch-project/security/pull/5339))

### Fixed
- Corrections in DlsFlsFilterLeafReader regarding PointVales and object valued attributes ([#5303](https://github.com/opensearch-project/security/pull/5303))
- Fix issue computing diffs in compliance audit log when writing to security index ([#5279](https://github.com/opensearch-project/security/pull/5279))
- Fixing dependabot broken pull_request workflow for changelog update ([#5331](https://github.com/opensearch-project/security/pull/5331))
- Fixes assemble workflow failure during Jenkins build ([#5334](https://github.com/opensearch-project/security/pull/5334))
- Fixes security index stale cache issue post snapshot restore ([#5307](https://github.com/opensearch-project/security/pull/5307))
- Only log Invalid Authentication header when HTTP Basic auth challenge is called ([#5377](https://github.com/opensearch-project/security/pull/5377))

### Security

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.0...main
