## Version 3.8.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.8.0

### Breaking Changes

* Remove `own_index` default roles mapping, requiring explicit configuration if needed ([#6147](https://github.com/opensearch-project/security/pull/6147))

### Features

* Implement standalone audit logging for SSL-only mode without requiring full security auth/RBAC ([#6304](https://github.com/opensearch-project/security/pull/6304))
* Add unified `disabled_categories` setting for audit logging ([#6271](https://github.com/opensearch-project/security/pull/6271))
* Allow read access on system indices marked with UnrestrictedSystemIndexDescriptor ([#6197](https://github.com/opensearch-project/security/pull/6197))
* Enforce 256 character limit on all text inputs for PUT/PATCH requests ([#6224](https://github.com/opensearch-project/security/pull/6224))
* Support query-based terms lookup queries in document-level security ([#6244](https://github.com/opensearch-project/security/pull/6244))
* Add support for `./gradlew run` task to allow running the plugin locally ([#6307](https://github.com/opensearch-project/security/pull/6307))

### Enhancements

* Scale legacy alias resolution with bounded indices-lookup access for improved performance on large clusters ([#6312](https://github.com/opensearch-project/security/pull/6312))
* Improve error message when unresolved user attributes are used in DLS to explicitly show "[none]" ([#6305](https://github.com/opensearch-project/security/pull/6305))
* Fix dynamic sign-in options by removing stale default and improving validation logic ([#6180](https://github.com/opensearch-project/security/pull/6180))
* Add `@Nullable` annotation to `assignResourceSharingClient` parameter to prevent NPE in Kotlin consumers ([#6301](https://github.com/opensearch-project/security/pull/6301))
* Address PR review feedback for standalone audit logging: add Sensitive property to settings, refactor index searcher wrapper, and use framework-level index resolution ([#6321](https://github.com/opensearch-project/security/pull/6321))

### Bug Fixes

* Fix API token count results returning empty when DLS/FLS layer blocks authorized requests ([#6218](https://github.com/opensearch-project/security/pull/6218))
* Fix Argon2PasswordHasher locale-sensitive `toUpperCase` bug causing failures in Turkish/Azerbaijani locales ([#6208](https://github.com/opensearch-project/security/pull/6208))
* Fix ClassCastException for otherName SAN entries during inter-cluster handshake ([#6137](https://github.com/opensearch-project/security/pull/6137))
* Fix `_cat/indices` returning 403 when `securitytenant` header is present ([#6284](https://github.com/opensearch-project/security/pull/6284))
* Fix Kafka sink test compatibility with Kafka 4.3 by using KafkaClusterTestKit directly ([#6225](https://github.com/opensearch-project/security/pull/6225))

### Infrastructure

* Adapt additional tests for testing conventions using randomized test base ([#6205](https://github.com/opensearch-project/security/pull/6205))
* Enable `bootstrap.serial_filter` in integration tests ([#6229](https://github.com/opensearch-project/security/pull/6229))
* Enable logger usage checks in security subprojects and update GitHub Actions Gradle steps ([#6210](https://github.com/opensearch-project/security/pull/6210))
* Enhance robustness of InternalOpenSearchSink tests through scenario-driven coverage and refactoring ([#6146](https://github.com/opensearch-project/security/pull/6146))
* Inline `get-opensearch-version` in create-bwc-build action to remove external dependency ([#6228](https://github.com/opensearch-project/security/pull/6228))
* Onboard new backport-pr reusable GitHub workflow ([#6250](https://github.com/opensearch-project/security/pull/6250))
* Replace `tibdex/github-app-token` with `actions/create-github-app-token` ([#6219](https://github.com/opensearch-project/security/pull/6219))
* Restore CI after setup-gradle v6 upgrade ([#6302](https://github.com/opensearch-project/security/pull/6302))
* Use opensearch-build start OpenSearch action in plugin install workflow ([#6216](https://github.com/opensearch-project/security/pull/6216))

### Maintenance

* Add Rishav Kumar as a co-maintainer of the Security repo ([#6223](https://github.com/opensearch-project/security/pull/6223))
* Bump 1password/load-secrets-action from 4.0.0 to 4.0.1 ([#6234](https://github.com/opensearch-project/security/pull/6234))
* Bump actions/checkout from 6.0.2 to 7.0.0 ([#6231](https://github.com/opensearch-project/security/pull/6231))
* Bump actions/setup-java from 5.2.0 to 5.4.0 ([#6256](https://github.com/opensearch-project/security/pull/6256))
* Bump actions/setup-java from 5.4.0 to 5.5.0 ([#6290](https://github.com/opensearch-project/security/pull/6290))
* Bump at.yawk.lz4:lz4-java from 1.11.0 to 1.11.1 ([#6319](https://github.com/opensearch-project/security/pull/6319))
* Bump aws-actions/configure-aws-credentials from 6.1.1 to 6.2.1 ([#6258](https://github.com/opensearch-project/security/pull/6258))
* Bump aws-actions/configure-aws-credentials from 6.2.1 to 6.2.2 ([#6314](https://github.com/opensearch-project/security/pull/6314))
* Bump ch.qos.logback:logback-classic from 1.5.34 to 1.5.37 ([#6260](https://github.com/opensearch-project/security/pull/6260))
* Bump ch.qos.logback:logback-classic from 1.5.37 to 1.5.38 ([#6298](https://github.com/opensearch-project/security/pull/6298))
* Bump codecov/codecov-action from 4.6.0 to 7.0.0 ([#6257](https://github.com/opensearch-project/security/pull/6257))
* Bump com.autonomousapps.build-health from 3.10.0 to 3.15.0 ([#6238](https://github.com/opensearch-project/security/pull/6238))
* Bump com.autonomousapps.build-health from 3.15.0 to 3.16.0 ([#6282](https://github.com/opensearch-project/security/pull/6282))
* Bump com.autonomousapps.build-health from 3.16.0 to 3.16.1 ([#6300](https://github.com/opensearch-project/security/pull/6300))
* Bump com.autonomousapps.build-health from 3.16.1 to 3.17.0 ([#6318](https://github.com/opensearch-project/security/pull/6318))
* Bump com.github.spotbugs from 6.5.5 to 6.5.8 ([#6263](https://github.com/opensearch-project/security/pull/6263))
* Bump com.github.spotbugs from 6.5.8 to 6.5.9 ([#6297](https://github.com/opensearch-project/security/pull/6297))
* Bump commons-logging:commons-logging from 1.3.6 to 1.4.0 ([#6240](https://github.com/opensearch-project/security/pull/6240))
* Bump github/codeql-action from 4.36.0 to 4.36.2 ([#6233](https://github.com/opensearch-project/security/pull/6233))
* Bump github/codeql-action/analyze from 4.36.3 to 4.37.0 ([#6292](https://github.com/opensearch-project/security/pull/6292))
* Bump github/codeql-action/analyze from 4.37.0 to 4.37.1 ([#6315](https://github.com/opensearch-project/security/pull/6315))
* Bump github/codeql-action/init from 4.36.2 to 4.36.3 ([#6281](https://github.com/opensearch-project/security/pull/6281))
* Bump github/codeql-action/init from 4.36.3 to 4.37.0 ([#6289](https://github.com/opensearch-project/security/pull/6289))
* Bump github/codeql-action/init from 4.37.0 to 4.37.1 ([#6313](https://github.com/opensearch-project/security/pull/6313))
* Bump gradle-wrapper from 9.5.1 to 9.6.1 ([#6262](https://github.com/opensearch-project/security/pull/6262))
* Bump io.dropwizard.metrics:metrics-core from 4.2.38 to 4.2.39 ([#6239](https://github.com/opensearch-project/security/pull/6239))
* Bump io.projectreactor:reactor-core from 3.8.5 to 3.8.6 ([#6214](https://github.com/opensearch-project/security/pull/6214))
* Bump kafka_version from 4.3.0 to 4.3.1 ([#6259](https://github.com/opensearch-project/security/pull/6259))
* Bump lycheeverse/lychee-action to 649b0e4890508ea3e11ea6b3ee35ce899a25afd5 ([#6291](https://github.com/opensearch-project/security/pull/6291))
* Bump net.bytebuddy:byte-buddy from 1.18.10 to 1.18.11 ([#6283](https://github.com/opensearch-project/security/pull/6283))
* Bump net.bytebuddy:byte-buddy from 1.18.8 to 1.18.10 ([#6261](https://github.com/opensearch-project/security/pull/6261))
* Bump open_saml from 5.2.2 to 5.2.3 ([#6237](https://github.com/opensearch-project/security/pull/6237))
* Bump open_saml_shib from 9.2.2 to 9.2.3 ([#6235](https://github.com/opensearch-project/security/pull/6235))
* Bump org.bouncycastle:bcpkix-jdk18on from 1.84 to 1.85 ([#6294](https://github.com/opensearch-project/security/pull/6294))
* Bump org.eclipse.platform:org.eclipse.equinox.common from 3.20.300 to 3.20.400 ([#6211](https://github.com/opensearch-project/security/pull/6211))
* Bump org.springframework.kafka:spring-kafka-test from 4.0.5 to 4.1.0 ([#6213](https://github.com/opensearch-project/security/pull/6213))
* Bump release-drafter/release-drafter from 7.3.0 to 7.5.1 ([#6280](https://github.com/opensearch-project/security/pull/6280))
* Bump release-drafter/release-drafter from 7.5.1 to 7.6.0 ([#6317](https://github.com/opensearch-project/security/pull/6317))
* Bump spring_framework from 7.0.7 to 7.0.8 ([#6212](https://github.com/opensearch-project/security/pull/6212))
* Bump stefanzweifel/git-auto-commit-action from 7.1.0 to 7.2.0 ([#6279](https://github.com/opensearch-project/security/pull/6279))

### Refactoring

* Convert multi-line strings to text blocks in BasicAuditlogTest ([#6220](https://github.com/opensearch-project/security/pull/6220))
