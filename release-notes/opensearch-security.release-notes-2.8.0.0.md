## 2023-06-06 Version 2.8.0.0

Compatible with OpenSearch 2.8.0

### Features

* Identify extension Transport requests and permit handshake and extension registration actions ([#2599](https://github.com/opensearch-project/security/pull/2599))
* Use ExtensionsManager.lookupExtensionSettingsById when verifying extension unique id ([#2749](https://github.com/opensearch-project/security/pull/2749))
* Generate auth tokens for service accounts ([#2716](https://github.com/opensearch-project/security/pull/2716))
* Security User Refactor ([#2594](https://github.com/opensearch-project/security/pull/2594))
* Add score based password verification ([#2557](https://github.com/opensearch-project/security/pull/2557))
* Usage of JWKS with JWT (w/o OpenID connect) ([#2808](https://github.com/opensearch-project/security/pull/2808))

### Bug Fixes

* `deserializeSafeFromHeader` uses `context.getHeader(headerName)` instead of `context.getHeaders()` ([#2768](https://github.com/opensearch-project/security/pull/2768))
* Fix multitency config update ([#2758](https://github.com/opensearch-project/security/pull/2758))

### Enhancements

* Add default roles for SQL plugin: PPL and cross-cluster search ([#2729](https://github.com/opensearch-project/security/pull/2729))
* Update security-analytics roles to add correlation engine apis ([#2732](https://github.com/opensearch-project/security/pull/2732))
* Changes in role.yml for long-running operation notification feature in Index-Management repo ([#2789](https://github.com/opensearch-project/security/pull/2789))
* Rest admin permissions ([#2411](https://github.com/opensearch-project/security/pull/2411))
* Separate config option to enable restapi: permissions ([#2605](https://github.com/opensearch-project/security/pull/2605))

### Maintenance

* Update to Gradle 8.1.1 ([#2738](https://github.com/opensearch-project/security/pull/2738))
* Upgrade spring-core from 5.3.26 to 5.3.27 ([#2717](https://github.com/opensearch-project/security/pull/2717))
