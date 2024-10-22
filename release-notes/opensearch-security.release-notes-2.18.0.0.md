## Version 2.18.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 2.18.0

### Enhancements
* Improve error message when a node with an incorrectly configured certificate attempts to connect ([#4819](https://github.com/opensearch-project/security/pull/4819))
* Support datastreams as an AuditLog Sink ([#4756](https://github.com/opensearch-project/security/pull/4756))
* Auto-convert V6 configuration instances into V7 configuration instances (for OpenSearch 2.x only) ([#4753](https://github.com/opensearch-project/security/pull/4753))
* Add can trip circuit breaker override ([#4779](https://github.com/opensearch-project/security/pull/4779))
* Adding index permissions for remote index in AD ([#4721](https://github.com/opensearch-project/security/pull/4721))
* Fix env var password hashing for PBKDF2 ([#4778](https://github.com/opensearch-project/security/pull/4778))
* Add ensureCustomSerialization to ensure that headers are serialized correctly with multiple transport hops ([#4741](https://github.com/opensearch-project/security/pull/4741))

### Bug Fixes
* Handle non-flat yaml settings for demo configuration detection ([#4798](https://github.com/opensearch-project/security/pull/4798))
* Fix bug where admin can read system index ([#4775](https://github.com/opensearch-project/security/pull/4775))
* Ensure that dual mode enabled flag from cluster settings can get propagated to core ([#4830](https://github.com/opensearch-project/security/pull/4830))
* Remove failed login attempt for saml authenticator ([#4770](https://github.com/opensearch-project/security/pull/4770))
* Fix issue in HashingStoredFieldVisitor with stored fields ([#4827](https://github.com/opensearch-project/security/pull/4827))
* Fix issue with Get mappings on a Closed index ([#4777](https://github.com/opensearch-project/security/pull/4777))
* changing comments permission for alerting_ack_alerts role ([#4723](https://github.com/opensearch-project/security/pull/4723))
* Fixed use of rolesMappingConfiguration in InternalUsersApiActionValidationTest ([#4754](https://github.com/opensearch-project/security/pull/4754))
* Use evaluateSslExceptionHandler() when constructing OpenSearchSecureSettingsFactory ([#4726](https://github.com/opensearch-project/security/pull/4726))

### Maintenance
* Bump gradle to 8.10.2 ([#4829](https://github.com/opensearch-project/security/pull/4829))
* Bump ch.qos.logback:logback-classic from 1.5.8 to 1.5.11 ([#4807](https://github.com/opensearch-project/security/pull/4807)) ([#4825](https://github.com/opensearch-project/security/pull/4825))
* Bump org.passay:passay from 1.6.5 to 1.6.6 ([#4824](https://github.com/opensearch-project/security/pull/4824))
* Bump org.junit.jupiter:junit-jupiter from 5.11.0 to 5.11.2 ([#4767](https://github.com/opensearch-project/security/pull/4767)) ([#4811](https://github.com/opensearch-project/security/pull/4811))
* Bump io.dropwizard.metrics:metrics-core from 4.2.27 to 4.2.28 ([#4789](https://github.com/opensearch-project/security/pull/4789))
* Bump com.nimbusds:nimbus-jose-jwt from 9.40 to 9.41.2 ([#4737](https://github.com/opensearch-project/security/pull/4737)) ([#4787](https://github.com/opensearch-project/security/pull/4787))
* Bump org.ow2.asm:asm from 9.7 to 9.7.1 ([#4788](https://github.com/opensearch-project/security/pull/4788))
* Bump com.google.googlejavaformat:google-java-format from 1.23.0 to 1.24.0 ([#4786](https://github.com/opensearch-project/security/pull/4786))
* Bump org.xerial.snappy:snappy-java from 1.1.10.6 to 1.1.10.7 ([#4738](https://github.com/opensearch-project/security/pull/4738))
* Bump org.gradle.test-retry from 1.5.10 to 1.6.0 ([#4736](https://github.com/opensearch-project/security/pull/4736))
* Moves @cliu123 to emeritus status ([#4667](https://github.com/opensearch-project/security/pull/4667))
* Add Derek Ho (github: derek-ho) as a maintainer ([#4796](https://github.com/opensearch-project/security/pull/4796))
* Add deprecation warning for GET/POST/PUT cache ([#4776](https://github.com/opensearch-project/security/pull/4776))
* Fix for: CVE-2024-47554 ([#4792](https://github.com/opensearch-project/security/pull/4792))
* Move Stephen to emeritus ([#4804](https://github.com/opensearch-project/security/pull/4804))
* Undeprecate securityadmin script ([#4768](https://github.com/opensearch-project/security/pull/4768))
* Bump commons-io:commons-io from 2.16.1 to 2.17.0 ([#4750](https://github.com/opensearch-project/security/pull/4750))
* Bump org.scala-lang:scala-library from 2.13.14 to 2.13.15 ([#4749](https://github.com/opensearch-project/security/pull/4749))
* org.checkerframework:checker-qual and ch.qos.logback:logback-classic to new versions ([#4717](https://github.com/opensearch-project/security/pull/4717))
* Add isActionPaginated to DelegatingRestHandler ([#4765](https://github.com/opensearch-project/security/pull/4765))
* Refactor ASN1 call ([#4740](https://github.com/opensearch-project/security/pull/4740))
* Fix 'integTest' not called with test workflows during release ([#4815](https://github.com/opensearch-project/security/pull/4815))
* Fixed bulk index requests in BWC tests and hardened assertions ([#4831](https://github.com/opensearch-project/security/pull/4831))
