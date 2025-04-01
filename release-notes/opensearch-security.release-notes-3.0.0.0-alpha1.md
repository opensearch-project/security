## Version 3.0.0-alpha1 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.0.0-alpha1

#### Breaking Changes
* Optimized Privilege Evaluation ([#4380](https://github.com/opensearch-project/security/pull/4380))
* Fix Blake2b hash implementation ([#5089](https://github.com/opensearch-project/security/pull/5089))

#### Enhancements
* Add support for CIDR ranges in `ignore_hosts` setting ([#5099](https://github.com/opensearch-project/security/pull/5099))
* Add 'good' as a valid value for `plugins.security.restapi.password_score_based_validation_strength` ([#5119](https://github.com/opensearch-project/security/pull/5119))
* Adding stop-replication permission to `index_management_full_access` ([#5160](https://github.com/opensearch-project/security/pull/5160))
* Replace password generator step with a secure password generator action ([#5153](https://github.com/opensearch-project/security/pull/5153))

#### Bug Fixes
* Fix version matcher string in demo config installer ([#5157](https://github.com/opensearch-project/security/pull/5157))

#### Maintenance
* Update AuditConfig.DEPRECATED_KEYS deprecation message to match 4.0 ([#5155](https://github.com/opensearch-project/security/pull/5155))
* Update deprecation message for `_opendistro/_security/kibanainfo` API ([#5156](https://github.com/opensearch-project/security/pull/5156))
* Update DlsFlsFilterLeafReader to reflect Apache Lucene 10 API changes ([#5123](https://github.com/opensearch-project/security/pull/5123))
* Adapt to core changes in `SecureTransportParameters` ([#5122](https://github.com/opensearch-project/security/pull/5122))
* Format SSLConfigConstants.java and fix typos ([#5145](https://github.com/opensearch-project/security/pull/5145))
* Remove typo in `AbstractAuditlogUnitTest` ([#5130](https://github.com/opensearch-project/security/pull/5130))
* Update Andriy Redko's affiliation ([#5133](https://github.com/opensearch-project/security/pull/5133))
* Upgrade common-utils version to `3.0.0.0-alpha1-SNAPSHOT` ([#5137](https://github.com/opensearch-project/security/pull/5137))
* Bump Spring version ([#5173](https://github.com/opensearch-project/security/pull/5173))
* Bump org.checkerframework:checker-qual from 3.49.0 to 3.49.1 ([#5162](https://github.com/opensearch-project/security/pull/5162))
* Bump org.mockito:mockito-core from 5.15.2 to 5.16.0 ([#5161](https://github.com/opensearch-project/security/pull/5161))
* Bump org.apache.camel:camel-xmlsecurity from 3.22.3 to 3.22.4 ([#5163](https://github.com/opensearch-project/security/pull/5163))
* Bump ch.qos.logback:logback-classic from 1.5.16 to 1.5.17 ([#5149](https://github.com/opensearch-project/security/pull/5149))
* Bump org.awaitility:awaitility from 4.2.2 to 4.3.0 ([#5126](https://github.com/opensearch-project/security/pull/5126))
* Bump org.springframework.kafka:spring-kafka-test from 3.3.2 to 3.3.3 ([#5125](https://github.com/opensearch-project/security/pull/5125))
* Bump org.junit.jupiter:junit-jupiter from 5.11.4 to 5.12.0 ([#5127](https://github.com/opensearch-project/security/pull/5127))
* Bump Gradle to 8.13 ([#5148](https://github.com/opensearch-project/security/pull/5148))
* Bump Spring version to fix CVE-2024-38827 ([#5173](https://github.com/opensearch-project/security/pull/5173))

