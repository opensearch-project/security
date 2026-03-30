# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added

### Changed

### Features

### Enhancements
- Make security plugin aware of FIPS build param (-Pcrypto.standard=FIPS-140-3) ([#5952](https://github.com/opensearch-project/security/pull/5952))
- Hardens input validation for resource sharing APIs ([#5831](https://github.com/opensearch-project/security/pull/5831)
- Optimize getFieldFilter to only return a predicate when index has FLS restrictions for user ([#5777](https://github.com/opensearch-project/security/pull/5777))
- Make `plugins.security.dfm_empty_overrides_all` dynamically toggleable ([#6016](https://github.com/opensearch-project/security/pull/6016)
- Performance optimizations for building internal authorization data structures upon config updates ([#5988](https://github.com/opensearch-project/security/pull/5988))
- Make encryption_key optional for obo token authenticator ([#6017](https://github.com/opensearch-project/security/pull/6017)
- [Resource Sharing] Using custom action prefixes for sample resource plugin ([#6020](https://github.com/opensearch-project/security/pull/6020)
- Enable basic authentication for gRPC transport ([#6005](https://github.com/opensearch-project/security/pull/6005))
- Allow specifying parentType and parentIdField in ResourceProvider ([#5735](https://github.com/opensearch-project/security/pull/5735))
- [Resource Sharing] Allow specifying default access level in resource access levels yml file ([#6018](https://github.com/opensearch-project/security/pull/6018))

### Bug Fixes
- Fix audit log writing errors for rollover-enabled alias indices ([#5878](https://github.com/opensearch-project/security/pull/5878)
- Fix the issue of unprocessed X-Request-Id ([#5954](https://github.com/opensearch-project/security/pull/5954))
- Fix audit log `NONE` sentinel not respected for `disabled_rest_categories`, `disabled_transport_categories`, and `ignore_users` in dynamic configuration ([#6021](https://github.com/opensearch-project/security/pull/6021))
- Improve DLS error message to identify undefined user attributes when query substitution fails ([#5975](https://github.com/opensearch-project/security/pull/5975))
- Fix span propagation issue for tracing([#6006](https://github.com/opensearch-project/security/pull/6006))

### Refactoring

### Maintenance
- Bump `commons-codec:commons-codec` from 1.20.0 to 1.21.0 ([#5937](https://github.com/opensearch-project/security/pull/5937))
- Bump `at.yawk.lz4:lz4-java` from 1.10.2 to 1.10.4 ([#5938](https://github.com/opensearch-project/security/pull/5938), [#5994](https://github.com/opensearch-project/security/pull/5994), [#6028](https://github.com/opensearch-project/security/pull/6028))
- Bump `open_saml_shib_version` from 9.1.6 to 9.2.1 ([#5936](https://github.com/opensearch-project/security/pull/5936), [#5982](https://github.com/opensearch-project/security/pull/5982))
- Bump `com.google.googlejavaformat:google-java-format` from 1.33.0 to 1.35.0 ([#5947](https://github.com/opensearch-project/security/pull/5947), [#6011](https://github.com/opensearch-project/security/pull/6011))
- Bump `aws-actions/configure-aws-credentials` from 5 to 6 ([#5946](https://github.com/opensearch-project/security/pull/5946))
- Bump `ch.qos.logback:logback-classic` from 1.5.26 to 1.5.32 ([#5948](https://github.com/opensearch-project/security/pull/5948), [#5995](https://github.com/opensearch-project/security/pull/5995))
- Bump `com.github.seancfoley:ipaddress` from 5.5.1 to 5.6.2 ([#5949](https://github.com/opensearch-project/security/pull/5949), [#6010](https://github.com/opensearch-project/security/pull/6010))
- Bump `spring_version` from 7.0.3 to 7.0.6 ([#5957](https://github.com/opensearch-project/security/pull/5957), [#5967](https://github.com/opensearch-project/security/pull/5967), [#6008](https://github.com/opensearch-project/security/pull/6008))
- Bump `org.junit.jupiter:junit-jupiter-api` from 5.14.2 to 5.14.3 ([#5956](https://github.com/opensearch-project/security/pull/5956))
- Bump `org.checkerframework:checker-qual` from 3.53.0 to 3.54.0 ([#5955](https://github.com/opensearch-project/security/pull/5955), [#6009](https://github.com/opensearch-project/security/pull/6009))
- Bump `open_saml_version` from 5.1.6 to 5.2.1 ([#5965](https://github.com/opensearch-project/security/pull/5965))
- Bump `kafka_version` from 4.1.1 to 4.2.0 ([#5968](https://github.com/opensearch-project/security/pull/5968))
- Bump `actions/upload-artifact` from 6 to 7 ([#5980](https://github.com/opensearch-project/security/pull/5980))
- Bump `actions/download-artifact` from 7 to 8 ([#5979](https://github.com/opensearch-project/security/pull/5979))
- Bump `jakarta.xml.bind:jakarta.xml.bind-api` from 4.0.4 to 4.0.5 ([#5978](https://github.com/opensearch-project/security/pull/5978))
- Bump `org.springframework.kafka:spring-kafka-test` from 4.0.2 to 4.0.4 ([#5981](https://github.com/opensearch-project/security/pull/5981), [#6026](https://github.com/opensearch-project/security/pull/6026))
- Bump `com.carrotsearch.randomizedtesting:randomizedtesting-runner` from 2.8.3 to 2.8.4 ([#5993](https://github.com/opensearch-project/security/pull/5993))
- Bump `gradle-wrapper` from 9.2.0 to 9.4.0 ([#5996](https://github.com/opensearch-project/security/pull/5996))
- Bump `release-drafter/release-drafter` from 6 to 7 ([#6007](https://github.com/opensearch-project/security/pull/6007))
- Bump `net.bytebuddy:byte-buddy` from 1.18.4 to 1.18.7 ([#6012](https://github.com/opensearch-project/security/pull/6012))
- Bump `com.nimbusds:nimbus-jose-jwt` from 10.7 to 10.8 ([#6030](https://github.com/opensearch-project/security/pull/6030))
- Bump `org.eclipse.platform:org.eclipse.core.runtime` from 3.34.100 to 3.34.200 ([#6027](https://github.com/opensearch-project/security/pull/6027))
- Bump `com.autonomousapps.build-health` from 3.5.1 to 3.6.1 ([#6029](https://github.com/opensearch-project/security/pull/6029))
- Bump `1password/load-secrets-action` from 3 to 4 ([#6047](https://github.com/opensearch-project/security/pull/6047))
- Bump `io.projectreactor:reactor-core` from 3.8.2 to 3.8.4 ([#6046](https://github.com/opensearch-project/security/pull/6046))
- Bump `commons-logging:commons-logging` from 1.3.5 to 1.3.6 ([#6050](https://github.com/opensearch-project/security/pull/6050))
- Bump `org.mockito:mockito-core` from 5.21.0 to 5.23.0 ([#6048](https://github.com/opensearch-project/security/pull/6048))

### Removed

### Documentation

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.5...main
