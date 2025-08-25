## Version 3.2.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.2.0

### Features

* Introduced new experimental versioned security configuration management feature ([#5357](https://github.com/opensearch-project/security/pull/5357))
* [Resource Sharing] Adds migrate API to move resource-sharing info to security plugin ([#5389](https://github.com/opensearch-project/security/pull/5389))
* Introduces support for the Argon2 Password Hashing Algorithm ([#5441](https://github.com/opensearch-project/security/pull/5441))
* Introduced permission validation support using query parameter without executing the request ([#5496](https://github.com/opensearch-project/security/pull/5496))
* Add support for configuring auxiliary transports for SSL only ([#5375](https://github.com/opensearch-project/security/pull/5375))
* Introduced SPIFFE X.509 SVID support via SPIFFEPrincipalExtractor ([#5521](https://github.com/opensearch-project/security/pull/5521))

### Enhancements

* Create a mechanism for plugins to explicitly declare actions they need to perform with their assigned PluginSubject ([#5341](https://github.com/opensearch-project/security/pull/5341))
* Moves OpenSAML jars to a Shadow Jar configuration to facilitate its use in FIPS enabled environments ([#5400](https://github.com/opensearch-project/security/pull/5404))
* [Resource Sharing] Adds a Resource Access Evaluator for standalone Resource access authorization ([#5408](https://github.com/opensearch-project/security/pull/5408))
* Replaced the standard distribution of BouncyCastle with BC-FIPS ([#5439](https://github.com/opensearch-project/security/pull/5439))
* Introduced setting `plugins.security.privileges_evaluation.precomputed_privileges.enabled` ([#5465](https://github.com/opensearch-project/security/pull/5465))
* Optimized wildcard matching runtime performance ([#5470](https://github.com/opensearch-project/security/pull/5470))
* Optimized performance for construction of internal action privileges data structure ([#5470](https://github.com/opensearch-project/security/pull/5470))
* Restricting query optimization via star tree index for users with queries on indices with DLS/FLS/FieldMasked restrictions ([#5492](https://github.com/opensearch-project/security/pull/5492))
* Handle subject in nested claim for JWT auth backends ([#5467](https://github.com/opensearch-project/security/pull/5467))
* Integration with stream transport ([#5530](https://github.com/opensearch-project/security/pull/5530))

### Bug Fixes

* Fix compilation issue after change to Subject interface in core and bump to 3.2.0 ([#5423](https://github.com/opensearch-project/security/pull/5423))
* Provide SecureHttpTransportParameters to complement SecureTransportParameters counterpart ([#5432](https://github.com/opensearch-project/security/pull/5432))
* Use isClusterPerm instead of requestedResolved.isLocalAll() to determine if action is a cluster action ([#5445](https://github.com/opensearch-project/security/pull/5445))
* Fix config update with deprecated config types failing in mixed clusters ([#5456](https://github.com/opensearch-project/security/pull/5456))
* Fix usage of jwt_clock_skew_tolerance_seconds in HTTPJwtAuthenticator ([#5506](https://github.com/opensearch-project/security/pull/5506))
* Always install demo certs if configured with demo certs ([#5517](https://github.com/opensearch-project/security/pull/5517))
* [Resource Sharing] Restores client accessor pattern to fix compilation issues when security plugin is not installed ([#5541](https://github.com/opensearch-project/security/pull/5541))

### Refactoring

* Refactor JWT Vendor to take a claims builder and rename oboEnabled to be enabled ([#5436](https://github.com/opensearch-project/security/pull/5436))
* Remove ASN1 reflection methods ([#5454](https://github.com/opensearch-project/security/pull/5454))
* Remove provider reflection code ([#5457](https://github.com/opensearch-project/security/pull/5457))
* Add tenancy access info to serialized user in threadcontext ([#5519](https://github.com/opensearch-project/security/pull/5519))