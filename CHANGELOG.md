# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]

### Features

### Enhancements

- [Resource Sharing] Keep track of list of principals for which sharable resource is visible for searching ([#5596](https://github.com/opensearch-project/security/pull/5596))
- [Resource Sharing] Keep track of tenant for sharable resources by persisting user requested tenant with sharing info ([#5588](https://github.com/opensearch-project/security/pull/5588))
- [SecurityPlugin Health Check] Add AuthZ initialization completion check in health check API [(#5626)](https://github.com/opensearch-project/security/pull/5626)

### Bug Fixes

- Added new option skip_users to client cert authenticator  (clientcert_auth_domain.http_authenticator.config.skip_users in config.yml)([#4378](https://github.com/opensearch-project/security/pull/5525))
- [Resource Sharing] Fixes accessible resource ids search by marking created_by.user field as keyword search instead of text ([#5574](https://github.com/opensearch-project/security/pull/5574))
- [Resource Sharing] Reverts @Inject pattern usage for ResourceSharingExtension to client accessor pattern. ([#5576](https://github.com/opensearch-project/security/pull/5576))
- Inject user custom attributes when injecting user and role information to the thread context ([#5560](https://github.com/opensearch-project/security/pull/5560))
- Allow any plugin system request when `plugins.security.system_indices.enabled` is set to `false` ([#5579](https://github.com/opensearch-project/security/pull/5579))
- [Resource Sharing] Always treat GET _doc request as indices request even when performed on sharable resource index ([#5631](https://github.com/opensearch-project/security/pull/5631))
- Fix JWT log spam when JWT authenticator is configured with an empty list for roles_key ([#5640](https://github.com/opensearch-project/security/pull/5640))

### Refactoring

- [Resource Sharing] Match index settings of .kibana indices for resource sharing indices ([#5605](https://github.com/opensearch-project/security/pull/5605))

### Maintenance
- Update delete_backport_branch workflow to include release-chores branches ([#5548](https://github.com/opensearch-project/security/pull/5548))
- Bump `1password/load-secrets-action` from 2 to 3 ([#5573](https://github.com/opensearch-project/security/pull/5573))
- Bump `jjwt_version` from 0.12.6 to 0.13.0 ([#5568](https://github.com/opensearch-project/security/pull/5568), [#5581](https://github.com/opensearch-project/security/pull/5581))
- Bump `org.mockito:mockito-core` from 5.18.0 to 5.19.0 ([#5566](https://github.com/opensearch-project/security/pull/5566))
- Bump `open_saml_version` from 5.1.4 to 5.1.6 ([#5567](https://github.com/opensearch-project/security/pull/5567), [#5614](https://github.com/opensearch-project/security/pull/5614))
- Bump `com.google.j2objc:j2objc-annotations` from 3.0.0 to 3.1 ([#5570](https://github.com/opensearch-project/security/pull/5570))
- Bump `spring_version` from 6.2.9 to 6.2.11 ([#5569](https://github.com/opensearch-project/security/pull/5569), [#5636](https://github.com/opensearch-project/security/pull/5636))
- Bump `com.github.spotbugs` from 6.2.4 to 6.4.1 ([#5584](https://github.com/opensearch-project/security/pull/5584), [#5611](https://github.com/opensearch-project/security/pull/5611), [#5637](https://github.com/opensearch-project/security/pull/5637))
- Bump `open_saml_shib_version` from 9.1.4 to 9.1.6 ([#5585](https://github.com/opensearch-project/security/pull/5585), [#5612](https://github.com/opensearch-project/security/pull/5612))
- Bump `org.springframework.kafka:spring-kafka-test` from 4.0.0-M3 to 4.0.0-M4 ([#5583](https://github.com/opensearch-project/security/pull/5583))
- Bump `net.bytebuddy:byte-buddy` from 1.17.6 to 1.17.7 ([#5586](https://github.com/opensearch-project/security/pull/5586))
- Bump `io.dropwizard.metrics:metrics-core` from 4.2.33 to 4.2.37 ([#5589](https://github.com/opensearch-project/security/pull/5589), [#5638](https://github.com/opensearch-project/security/pull/5638))
- Bump `com.nimbusds:nimbus-jose-jwt:9.48` from 9.48 to 10.4.2 ([#5595](https://github.com/opensearch-project/security/pull/5595))
- Bump `actions/github-script` from 7 to 8 ([#5610](https://github.com/opensearch-project/security/pull/5610))
- Bump `org.eclipse.platform:org.eclipse.core.runtime` from 3.33.100 to 3.34.0 ([#5628](https://github.com/opensearch-project/security/pull/5628))
- Bump `org.opensearch:protobufs` from 0.6.0 to 0.13.0 ([#5553](https://github.com/opensearch-project/security/pull/5553))
- Bump `org.checkerframework:checker-qual` from 3.49.5 to 3.51.0 ([#5627](https://github.com/opensearch-project/security/pull/5627))
- Bump `com.nimbusds:nimbus-jose-jwt` from 10.4.2 to 10.5 ([#5629](https://github.com/opensearch-project/security/pull/5629))
- Bump `derek-ho/start-opensearch` from 7 to 8 ([#5630](https://github.com/opensearch-project/security/pull/5630))
- Bump `jakarta.xml.bind:jakarta.xml.bind-api` from 4.0.2 to 4.0.4 ([#5649](https://github.com/opensearch-project/security/pull/5649))
- Bump `com.google.errorprone:error_prone_annotations` from 2.41.0 to 2.42.0 ([#5648](https://github.com/opensearch-project/security/pull/5648))

### Documentation

- [Resource Sharing] Adds comprehensive documentation for Resource Access Control feature ([#5540](https://github.com/opensearch-project/security/pull/5540))

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.2...main
