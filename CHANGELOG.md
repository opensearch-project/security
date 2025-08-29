# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]

### Features

### Enhancements

### Bug Fixes

* Added new option skip_users to client cert authenticator  (clientcert_auth_domain.http_authenticator.config.skip_users in config.yml)([#4378](https://github.com/opensearch-project/security/pull/5525))
* [Resource Sharing] Fixes accessible resource ids search by marking created_by.user field as keyword search instead of text ([#5574](https://github.com/opensearch-project/security/pull/5574))
* [Resource Sharing] Reverts @Inject pattern usage for ResourceSharingExtension to client accessor pattern. ([#5576](https://github.com/opensearch-project/security/pull/5576))
* Inject user custom attributes when injecting user and role information to the thread context ([#5560](https://github.com/opensearch-project/security/pull/5560))
* Allow any plugin system request when `plugins.security.system_indices.enabled` is set to `false` ([#5579](https://github.com/opensearch-project/security/pull/5579))

### Refactoring

### Maintenance

- Bump `org.eclipse.platform:org.eclipse.core.runtime` from 3.33.0 to 3.33.100 ([#5400](https://github.com/opensearch-project/security/pull/5400))
- Bump `org.eclipse.platform:org.eclipse.equinox.common` from 3.20.0 to 3.20.100 ([#5402](https://github.com/opensearch-project/security/pull/5402))
- Bump `spring_version` from 6.2.7 to 6.2.9 ([#5403](https://github.com/opensearch-project/security/pull/5403), [#5493](https://github.com/opensearch-project/security/pull/5493))
- Bump `stefanzweifel/git-auto-commit-action` from 5 to 6 ([#5401](https://github.com/opensearch-project/security/pull/5401))
- Bump `com.github.spotbugs` from 5.2.5 to 6.2.3 ([#5409](https://github.com/opensearch-project/security/pull/5409), [#5450](https://github.com/opensearch-project/security/pull/5450), [#5474](https://github.com/opensearch-project/security/pull/5474), [#5536](https://github.com/opensearch-project/security/pull/5536))
- Bump `org.codehaus.plexus:plexus-utils` from 3.3.0 to 3.6.0 ([#5429](https://github.com/opensearch-project/security/pull/5429))
- Bump `net.bytebuddy:byte-buddy` from 1.17.5 to 1.17.6 ([#5427](https://github.com/opensearch-project/security/pull/5427))
- Bump `io.dropwizard.metrics:metrics-core` from 4.2.32 to 4.2.33 ([#5428](https://github.com/opensearch-project/security/pull/5428))
- Bump `org.junit.jupiter:junit-jupiter-api` from 5.13.1 to 5.13.2 ([#5446](https://github.com/opensearch-project/security/pull/5446))
- Bump `com.google.errorprone:error_prone_annotations` from 2.38.0 to 2.41.0 ([#5447](https://github.com/opensearch-project/security/pull/5447), [#5477](https://github.com/opensearch-project/security/pull/5477), [#5512](https://github.com/opensearch-project/security/pull/5512), [#5532](https://github.com/opensearch-project/security/pull/5532))
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
- Bumps opensearch-protobufs plugin version to 0.6.0 ([#5529](https://github.com/opensearch-project/security/pull/5529))
- Bump `net.minidev:accessors-smart` from 2.5.2 to 2.6.0 ([#5535](https://github.com/opensearch-project/security/pull/5535))
- Bump `commons-codec:commons-codec` from 1.18.0 to 1.19.0 ([#5534](https://github.com/opensearch-project/security/pull/5534))
- Bump `commons-cli:commons-cli` from 1.9.0 to 1.10.0 ([#5533](https://github.com/opensearch-project/security/pull/5533))
- Bump `checkstyle` to 11.0.0 and `spotbugs` to 6.2.4 ([#5555](https://github.com/opensearch-project/security/pull/5555))
- Removes `commons-io` and `commons-lang3` maven metadata from shaded opensaml jar to fix CVE-2024-47554 ([#5558](https://github.com/opensearch-project/security/pull/5558))
- Update delete_backport_branch workflow to include release-chores branches ([#5548](https://github.com/opensearch-project/security/pull/5548))
- Bump `1password/load-secrets-action` from 2 to 3 ([#5573](https://github.com/opensearch-project/security/pull/5573))
- Bump `jjwt_version` from 0.12.6 to 0.13.0 ([#5568](https://github.com/opensearch-project/security/pull/5568), [#5581](https://github.com/opensearch-project/security/pull/5581))
- Bump `org.mockito:mockito-core` from 5.18.0 to 5.19.0 ([#5566](https://github.com/opensearch-project/security/pull/5566))
- Bump `open_saml_version` from 5.1.4 to 5.1.5 ([#5567](https://github.com/opensearch-project/security/pull/5567))
- Bump `com.google.j2objc:j2objc-annotations` from 3.0.0 to 3.1 ([#5570](https://github.com/opensearch-project/security/pull/5570))
- Bump `spring_version` from 6.2.9 to 6.2.10 ([#5569](https://github.com/opensearch-project/security/pull/5569))
- Bump `com.github.spotbugs` from 6.2.4 to 6.2.5 ([#5584](https://github.com/opensearch-project/security/pull/5584))
- Bump `open_saml_shib_version` from 9.1.4 to 9.1.5 ([#5585](https://github.com/opensearch-project/security/pull/5585))
- Bump `org.springframework.kafka:spring-kafka-test` from 4.0.0-M3 to 4.0.0-M4 ([#5583](https://github.com/opensearch-project/security/pull/5583))
- Bump `net.bytebuddy:byte-buddy` from 1.17.6 to 1.17.7 ([#5586](https://github.com/opensearch-project/security/pull/5586))
- Bump `io.dropwizard.metrics:metrics-core` from 4.2.33 to 4.2.34 ([#5589](https://github.com/opensearch-project/security/pull/5589))
- Bump `com.nimbusds:nimbus-jose-jwt:9.48` from 9.48 to 10.4.2 ([#5595](https://github.com/opensearch-project/security/pull/5595))

### Documentation

- [Resource Sharing] Adds comprehensive documentation for Resource Access Control feature ([#5540](https://github.com/opensearch-project/security/pull/5540))

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.2...main
