## Version 3.0.0-beta1 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.0.0-beta1

#### Breaking Changes
* Fix Blake2b hash implementation ([#5089](https://github.com/opensearch-project/security/pull/5089))
* Remove OpenSSL provider ([#5220](https://github.com/opensearch-project/security/pull/5220))
* Remove whitelist settings in favor of allowlist ([#5224](https://github.com/opensearch-project/security/pull/5224))

#### Enhancements
* Optimized Privilege Evaluation ([#4380](https://github.com/opensearch-project/security/pull/4380))
* Add support for CIDR ranges in `ignore_hosts` setting ([#5099](https://github.com/opensearch-project/security/pull/5099))
* Add 'good' as a valid value for `plugins.security.restapi.password_score_based_validation_strength` ([#5119](https://github.com/opensearch-project/security/pull/5119))
* Adding stop-replication permission to `index_management_full_access` ([#5160](https://github.com/opensearch-project/security/pull/5160))
* Replace password generator step with a secure password generator action ([#5153](https://github.com/opensearch-project/security/pull/5153))
* Run Security build on image from opensearch-build ([#4966](https://github.com/opensearch-project/security/pull/4966))

#### Bug Fixes
* Fix version matcher string in demo config installer ([#5157](https://github.com/opensearch-project/security/pull/5157))
* Escape pipe character for injected users ([#5175](https://github.com/opensearch-project/security/pull/5175))
* Assume default of v7 models if _meta portion is not present ([#5193](https://github.com/opensearch-project/security/pull/5193))
* Fixed IllegalArgumentException when building stateful index privileges ([#5217](https://github.com/opensearch-project/security/pull/5217))
* DlsFlsFilterLeafReader::termVectors implementation causes assertion errors for users with FLS/FM active ([#5243](https://github.com/opensearch-project/security/pull/5243))

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
* Bump org.checkerframework:checker-qual from 3.49.0 to 3.49.2 ([#5162](https://github.com/opensearch-project/security/pull/5162)) ([#5247](https://github.com/opensearch-project/security/pull/5247))
* Bump org.mockito:mockito-core from 5.15.2 to 5.17.0 ([#5161](https://github.com/opensearch-project/security/pull/5161)) ([#5248](https://github.com/opensearch-project/security/pull/5248))
* Bump org.apache.camel:camel-xmlsecurity from 3.22.3 to 3.22.4 ([#5163](https://github.com/opensearch-project/security/pull/5163))
* Bump ch.qos.logback:logback-classic from 1.5.16 to 1.5.17 ([#5149](https://github.com/opensearch-project/security/pull/5149))
* Bump org.awaitility:awaitility from 4.2.2 to 4.3.0 ([#5126](https://github.com/opensearch-project/security/pull/5126))
* Bump org.springframework.kafka:spring-kafka-test from 3.3.2 to 3.3.4 ([#5125](https://github.com/opensearch-project/security/pull/5125)) ([#5201](https://github.com/opensearch-project/security/pull/5201))
* Bump org.junit.jupiter:junit-jupiter from 5.11.4 to 5.12.0 ([#5127](https://github.com/opensearch-project/security/pull/5127))
* Bump Gradle to 8.13 ([#5148](https://github.com/opensearch-project/security/pull/5148))
* Bump Spring version to fix CVE-2024-38827 ([#5173](https://github.com/opensearch-project/security/pull/5173))
* Bump com.google.guava:guava from 33.4.0-jre to 33.4.6-jre ([#5205](https://github.com/opensearch-project/security/pull/5205)) ([#5228](https://github.com/opensearch-project/security/pull/5228))
* Bump ch.qos.logback:logback-classic from 1.5.17 to 1.5.18 ([#5204](https://github.com/opensearch-project/security/pull/5204))
* Bump spring_version from 6.2.4 to 6.2.5 ([#5203](https://github.com/opensearch-project/security/pull/5203))
* Bump bouncycastle_version from 1.78 to 1.80 ([#5202](https://github.com/opensearch-project/security/pull/5202))
* remove java version check for reflection args in build.gradle ([#5218](https://github.com/opensearch-project/security/pull/5218))
* Improve coverage: Adding tests for ConfigurationRepository class ([#5206](https://github.com/opensearch-project/security/pull/5206))
* Refactor InternalAuditLogTest to use Awaitility ([#5214](https://github.com/opensearch-project/security/pull/5214))
* Bump com.google.googlejavaformat:google-java-format from 1.25.2 to 1.26.0 ([#5231](https://github.com/opensearch-project/security/pull/5231))
* Bump open_saml_shib_version from 9.1.3 to 9.1.4 ([#5230](https://github.com/opensearch-project/security/pull/5230))
* Bump com.carrotsearch.randomizedtesting:randomizedtesting-runner from 2.8.2 to 2.8.3 ([#5229](https://github.com/opensearch-project/security/pull/5229))
* Bump open_saml_version from 5.1.3 to 5.1.4 ([#5227](https://github.com/opensearch-project/security/pull/5227))
* Bump org.ow2.asm:asm from 9.7.1 to 9.8 ([#5244](https://github.com/opensearch-project/security/pull/5244))
* Bump com.netflix.nebula.ospackage from 11.11.1 to 11.11.2 ([#5246](https://github.com/opensearch-project/security/pull/5246))
* Bump com.google.errorprone:error_prone_annotations from 2.36.0 to 2.37.0 ([#5245](https://github.com/opensearch-project/security/pull/5245))
* More tests for FLS and field masking ([#5237](https://github.com/opensearch-project/security/pull/5237))
* Migrate from com.amazon.dlic to org.opensearch.security package ([#5223](https://github.com/opensearch-project/security/pull/5223))
