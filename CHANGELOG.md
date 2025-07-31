# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]

### Features

* Introduced new experimental versioned security configuration management feature ([#5357] (https://github.com/opensearch-project/security/pull/5357))
* [Resource Sharing] Adds migrate API to move resource-sharing info to security plugin ([#5389](https://github.com/opensearch-project/security/pull/5389))
* Introduces support for the Argon2 Password Hashing Algorithm ([#5441] (https://github.com/opensearch-project/security/pull/5441))
* Introduced permission validation support using query parameter without executing the request ([#5496](https://github.com/opensearch-project/security/pull/5496))
* Introduced SPIFFE X.509 SVID support via SPIFFEPrincipalExtractor ([#5521](https://github.com/opensearch-project/security/pull/5521))

### Enhancements

* Create a mechanism for plugins to explicitly declare actions they need to perform with their assigned PluginSubject ([#5341](https://github.com/opensearch-project/security/pull/5341))
* Moves OpenSAML jars to a Shadow Jar configuration to facilitate its use in FIPS enabled environments ([#5400](https://github.com/opensearch-project/security/pull/5404))
* Replaced the standard distribution of BouncyCastle with BC-FIPS ([#5439](https://github.com/opensearch-project/security/pull/5439))
* Introduced setting `plugins.security.privileges_evaluation.precomputed_privileges.enabled` ([#5465](https://github.com/opensearch-project/security/pull/5465))
* Optimized wildcard matching runtime performance ([#5470](https://github.com/opensearch-project/security/pull/5470))
* Optimized performance for construction of internal action privileges data structure  ([#5470](https://github.com/opensearch-project/security/pull/5470))
* Restricting query optimization via star tree index for users with queries on indices with DLS/FLS/FieldMasked restrictions ([#5492](https://github.com/opensearch-project/security/pull/5492))
* Handle subject in nested claim for JWT auth backends ([#5467](https://github.com/opensearch-project/security/pull/5467))

### Bug Fixes

* Fix compilation issue after change to Subject interface in core and bump to 3.2.0 ([#5423](https://github.com/opensearch-project/security/pull/5423))
* Provide SecureHttpTransportParameters to complement SecureTransportParameters counterpart ([#5432](https://github.com/opensearch-project/security/pull/5432))
* Use isClusterPerm instead of requestedResolved.isLocalAll() to determine if action is a cluster action ([#5445](https://github.com/opensearch-project/security/pull/5445))
* Fix config update with deprecated config types failing in mixed clusters ([#5456](https://github.com/opensearch-project/security/pull/5456))
* Fix usage of jwt_clock_skew_tolerance_seconds in HTTPJwtAuthenticator ([#5506](https://github.com/opensearch-project/security/pull/5506))

### Refactoring

* Refactor JWT Vender to take a claims builder and rename oboEnabled to enabled ([#5436](https://github.com/opensearch-project/security/pull/5436))
* Remove ASN1 reflection methods ([#5454](https://github.com/opensearch-project/security/pull/5454))
* Remove provider reflection code ([#5457](https://github.com/opensearch-project/security/pull/5457))
* Add tenancy access info to serialized user in threadcontext ([#5519](https://github.com/opensearch-project/security/pull/5519))

### Maintenance
- Bump `org.eclipse.platform:org.eclipse.core.runtime` from 3.33.0 to 3.33.100 ([#5400](https://github.com/opensearch-project/security/pull/5400))
- Bump `org.eclipse.platform:org.eclipse.equinox.common` from 3.20.0 to 3.20.100 ([#5402](https://github.com/opensearch-project/security/pull/5402))
- Bump `spring_version` from 6.2.7 to 6.2.9 ([#5403](https://github.com/opensearch-project/security/pull/5403), [#5493](https://github.com/opensearch-project/security/pull/5493))
- Bump `stefanzweifel/git-auto-commit-action` from 5 to 6 ([#5401](https://github.com/opensearch-project/security/pull/5401))
- Bump `com.github.spotbugs` from 5.2.5 to 6.2.2 ([#5409](https://github.com/opensearch-project/security/pull/5409), [#5450](https://github.com/opensearch-project/security/pull/5450), [#5474](https://github.com/opensearch-project/security/pull/5474))
- Bump `org.codehaus.plexus:plexus-utils` from 3.3.0 to 3.6.0 ([#5429](https://github.com/opensearch-project/security/pull/5429))
- Bump `net.bytebuddy:byte-buddy` from 1.17.5 to 1.17.6 ([#5427](https://github.com/opensearch-project/security/pull/5427))
- Bump `io.dropwizard.metrics:metrics-core` from 4.2.32 to 4.2.33 ([#5428](https://github.com/opensearch-project/security/pull/5428))
- Bump `org.junit.jupiter:junit-jupiter-api` from 5.13.1 to 5.13.2 ([#5446](https://github.com/opensearch-project/security/pull/5446))
- Bump `com.google.errorprone:error_prone_annotations` from 2.38.0 to 2.41.0 ([#5447](https://github.com/opensearch-project/security/pull/5447), [#5477](https://github.com/opensearch-project/security/pull/5477), [#5512](https://github.com/opensearch-project/security/pull/5512))
- Bump `io.dropwizard.metrics:metrics-core` from 4.2.32 to 4.2.33 ([#5428](https://github.com/opensearch-project/security/pull/5428))
- Bump `org.junit.jupiter:junit-jupiter` from 5.13.2 to 5.13.4 ([#5460](https://github.com/opensearch-project/security/pull/5460), [#5513](https://github.com/opensearch-project/security/pull/5513))
- Bump `org.checkerframework:checker-qual` from 3.49.4 to 3.49.5 ([#5462](https://github.com/opensearch-project/security/pull/5462))
- Bump `com.google.googlejavaformat:google-java-format` from 1.27.0 to 1.28.0 ([#5475](https://github.com/opensearch-project/security/pull/5475))
- Bump `commons-validator:commons-validator` from 1.9.0 to 1.10.0 ([#5476](https://github.com/opensearch-project/security/pull/5476))
- Bumps checkstyle to 10.26.1 that fixes CVE-2025-48734 ([#5485](https://github.com/opensearch-project/security/pull/5485))
- Bump `commons-io:commons-io` from 2.19.0 to 2.20.0 ([#5494](https://github.com/opensearch-project/security/pull/5494))
- Bump `org.xerial.snappy:snappy-java` from 1.1.10.7 to 1.1.10.8 ([#5495](https://github.com/opensearch-project/security/pull/5495))
- Bump `org.apache.commons:commons-text` from 1.13.1 to 1.14.0 ([#5511](https://github.com/opensearch-project/security/pull/5511))
- Bump `org.springframework.kafka:spring-kafka-test` from 4.0.0-M2 to 4.0.0-M3 ([#5514](https://github.com/opensearch-project/security/pull/5514))

### Documentation

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.1...main
