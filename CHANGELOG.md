# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added

### Features

### Enhancements
- Makes resource settings dynamic ([#5677](https://github.com/opensearch-project/security/pull/5677))

### Bug Fixes
- Create a WildcardMatcher.NONE when creating a WildcardMatcher with an empty string ([#5694](https://github.com/opensearch-project/security/pull/5694))
- Improve array validator to also check for blank string in addition to null ([#5714](https://github.com/opensearch-project/security/pull/5714))
- Use RestRequestFilter.getFilteredRequest to declare sensitive API params ([#5710](https://github.com/opensearch-project/security/pull/5710))
- Fix deprecated SSL transport settings in demo certificates ([#5723](https://github.com/opensearch-project/security/pull/5723))
- Updates DlsFlsValveImpl condition to return true if request is internal and not a protected resource request ([#5721](https://github.com/opensearch-project/security/pull/5721))

### Refactoring
- [Resource Sharing] Make migrate api require default access level to be supplied and updates documentations + tests ([#5717](https://github.com/opensearch-project/security/pull/5717))
- [Resource Sharing] Removes share and revoke java APIs ([#5718](https://github.com/opensearch-project/security/pull/5718))

### Maintenance
- Bump `org.junit.jupiter:junit-jupiter` from 5.13.4 to 5.14.0 ([#5678](https://github.com/opensearch-project/security/pull/5678))
- Bump `ch.qos.logback:logback-classic` from 1.5.18 to 1.5.20 ([#5680](https://github.com/opensearch-project/security/pull/5680), [#5724](https://github.com/opensearch-project/security/pull/5724))
- Bump `org.scala-lang:scala-library` from 2.13.16 to 2.13.17 ([#5682](https://github.com/opensearch-project/security/pull/5682))
- Bump `org.gradle.test-retry` from 1.6.2 to 1.6.4 ([#5706](https://github.com/opensearch-project/security/pull/5706))
- Bump `org.checkerframework:checker-qual` from 3.51.0 to 3.51.1 ([#5705](https://github.com/opensearch-project/security/pull/5705))
- Bump `org.ow2.asm:asm` from 9.8 to 9.9 ([#5707](https://github.com/opensearch-project/security/pull/5707))
- Bump `stefanzweifel/git-auto-commit-action` from 6 to 7 ([#5704](https://github.com/opensearch-project/security/pull/5704))
- Bump `net.bytebuddy:byte-buddy` from 1.17.7 to 1.17.8 ([#5703](https://github.com/opensearch-project/security/pull/5703))
- Bump `derek-ho/start-opensearch` from 7 to 9 ([#5630](https://github.com/opensearch-project/security/pull/5630), [#5679](https://github.com/opensearch-project/security/pull/5679))
- Bump `github/codeql-action` from 3 to 4 ([#5702](https://github.com/opensearch-project/security/pull/5702))
- Bump `com.github.spotbugs` from 6.4.2 to 6.4.4 ([#5727](https://github.com/opensearch-project/security/pull/5727))
- Bump `com.autonomousapps.build-health` from 3.0.4 to 3.1.0 ([#5726](https://github.com/opensearch-project/security/pull/5726))
- Bump `spring_version` from 6.2.11 to 6.2.12 ([#5725](https://github.com/opensearch-project/security/pull/5725))

### Documentation

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.3...main
