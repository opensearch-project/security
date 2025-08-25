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

### Refactoring

### Maintenance
- Bump `1password/load-secrets-action` from 2 to 3 ([#5573](https://github.com/opensearch-project/security/pull/5573))
- Bump `jjwt_version` from 0.12.6 to 0.13.0 ([#5568](https://github.com/opensearch-project/security/pull/5568), [#5581](https://github.com/opensearch-project/security/pull/5581))
- Bump `org.mockito:mockito-core` from 5.18.0 to 5.19.0 ([#5566](https://github.com/opensearch-project/security/pull/5566))
- Bump `open_saml_version` from 5.1.4 to 5.1.5 ([#5567](https://github.com/opensearch-project/security/pull/5567))
- Bump `com.google.j2objc:j2objc-annotations` from 3.0.0 to 3.1 ([#5570](https://github.com/opensearch-project/security/pull/5570))
- Bump `spring_version` from 6.2.9 to 6.2.10 ([#5569](https://github.com/opensearch-project/security/pull/5569))
- Bump `com.github.spotbugs` from 6.2.4 to 6.2.5 ([#5584](https://github.com/opensearch-project/security/pull/5584))
- Bump `open_saml_shib_version` from 9.1.4 to 9.1.5 ([#5585](https://github.com/opensearch-project/security/pull/5585))

### Documentation

- [Resource Sharing] Adds comprehensive documentation for Resource Access Control feature ([#5540](https://github.com/opensearch-project/security/pull/5540))

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.2...main
