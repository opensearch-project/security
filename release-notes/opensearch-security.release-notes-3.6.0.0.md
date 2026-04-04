## Version 3.6.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.6.0

### Features

* Enable Basic Authentication for gRPC transport ([#6005](https://github.com/opensearch-project/security/pull/6005))
* Allow specifying parentType and parentIdField in ResourceProvider for parent-child resource authorization ([#5735](https://github.com/opensearch-project/security/pull/5735))

### Enhancements

* Optimize getFieldFilter to only return a predicate when an index has FLS restrictions for the user ([#5777](https://github.com/opensearch-project/security/pull/5777))
* Optimize string matching for RoleBasedActionPrivileges with prefix and exact pattern matching ([#5988](https://github.com/opensearch-project/security/pull/5988))
* Harden input validation for resource sharing APIs by introducing parameter limits ([#5831](https://github.com/opensearch-project/security/pull/5831))
* Make encryption_key optional for on-behalf-of token authenticator ([#6017](https://github.com/opensearch-project/security/pull/6017))
* Allow specifying default access level in resource access levels YAML file ([#6018](https://github.com/opensearch-project/security/pull/6018))
* Use custom action prefixes for sample resource plugin ([#6020](https://github.com/opensearch-project/security/pull/6020))
* Make security plugin aware of FIPS build parameter for BouncyCastle FIPS jar handling ([#5952](https://github.com/opensearch-project/security/pull/5952))

### Bug Fixes

* Fix propagation issue for security context ([#6006](https://github.com/opensearch-project/security/pull/6006))
* Fix audit log writing errors for rollover-enabled alias indices ([#5900](https://github.com/opensearch-project/security/pull/5900))
* Fix unprocessed X-Request-Id header in requests ([#5954](https://github.com/opensearch-project/security/pull/5954))
* Fix audit log NONE sentinel value not respected in dynamic configuration and misleading unknown setting error ([#6021](https://github.com/opensearch-project/security/pull/6021))
* Improve error message for DLS queries referencing undefined user attributes ([#5975](https://github.com/opensearch-project/security/pull/5975))

### Maintenance

* Bump actions/download-artifact from 7 to 8 ([#5979](https://github.com/opensearch-project/security/pull/5979))
* Bump actions/upload-artifact from 6 to 7 ([#5980](https://github.com/opensearch-project/security/pull/5980))
* Bump at.yawk.lz4:lz4-java from 1.10.3 to 1.10.4 ([#5994](https://github.com/opensearch-project/security/pull/5994))
* Bump at.yawk.lz4:lz4-java from 1.10.3 to 1.10.4 ([#6028](https://github.com/opensearch-project/security/pull/6028))
* Bump aws-actions/configure-aws-credentials from 5 to 6 ([#5946](https://github.com/opensearch-project/security/pull/5946))
* Bump ch.qos.logback:logback-classic from 1.5.26 to 1.5.28 ([#5948](https://github.com/opensearch-project/security/pull/5948))
* Bump ch.qos.logback:logback-classic from 1.5.28 to 1.5.32 ([#5995](https://github.com/opensearch-project/security/pull/5995))
* Bump com.autonomousapps.build-health from 3.5.1 to 3.6.1 ([#6029](https://github.com/opensearch-project/security/pull/6029))
* Bump com.carrotsearch.randomizedtesting:randomizedtesting-runner from 2.8.3 to 2.8.4 ([#5993](https://github.com/opensearch-project/security/pull/5993))
* Bump com.github.seancfoley:ipaddress from 5.5.1 to 5.6.1 ([#5949](https://github.com/opensearch-project/security/pull/5949))
* Bump com.github.seancfoley:ipaddress from 5.6.1 to 5.6.2 ([#6010](https://github.com/opensearch-project/security/pull/6010))
* Bump com.google.googlejavaformat:google-java-format from 1.33.0 to 1.34.1 ([#5947](https://github.com/opensearch-project/security/pull/5947))
* Bump com.google.googlejavaformat:google-java-format from 1.34.1 to 1.35.0 ([#6011](https://github.com/opensearch-project/security/pull/6011))
* Bump com.nimbusds:nimbus-jose-jwt from 10.7 to 10.8 ([#6030](https://github.com/opensearch-project/security/pull/6030))
* Bump gradle-wrapper from 9.2.0 to 9.4.0 ([#5996](https://github.com/opensearch-project/security/pull/5996))
* Bump jakarta.xml.bind:jakarta.xml.bind-api from 4.0.4 to 4.0.5 ([#5978](https://github.com/opensearch-project/security/pull/5978))
* Bump kafka_version from 4.1.1 to 4.2.0 ([#5968](https://github.com/opensearch-project/security/pull/5968))
* Bump net.bytebuddy:byte-buddy from 1.18.4 to 1.18.7 ([#6012](https://github.com/opensearch-project/security/pull/6012))
* Bump open_saml_shib_version from 9.2.0 to 9.2.1 ([#5982](https://github.com/opensearch-project/security/pull/5982))
* Bump open_saml_version from 5.1.6 to 5.2.1 ([#5965](https://github.com/opensearch-project/security/pull/5965))
* Bump org.checkerframework:checker-qual from 3.53.0 to 3.53.1 ([#5955](https://github.com/opensearch-project/security/pull/5955))
* Bump org.checkerframework:checker-qual from 3.53.1 to 3.54.0 ([#6009](https://github.com/opensearch-project/security/pull/6009))
* Bump org.eclipse.platform:org.eclipse.core.runtime from 3.34.100 to 3.34.200 ([#6027](https://github.com/opensearch-project/security/pull/6027))
* Bump org.junit.jupiter:junit-jupiter-api from 5.14.2 to 5.14.3 ([#5956](https://github.com/opensearch-project/security/pull/5956))
* Bump org.springframework.kafka:spring-kafka-test from 4.0.2 to 4.0.3 ([#5981](https://github.com/opensearch-project/security/pull/5981))
* Bump org.springframework.kafka:spring-kafka-test from 4.0.3 to 4.0.4 ([#6026](https://github.com/opensearch-project/security/pull/6026))
* Bump release-drafter/release-drafter from 6 to 7 ([#6007](https://github.com/opensearch-project/security/pull/6007))
* Bump spring_version from 7.0.3 to 7.0.4 ([#5957](https://github.com/opensearch-project/security/pull/5957))
* Bump spring_version from 7.0.4 to 7.0.5 ([#5967](https://github.com/opensearch-project/security/pull/5967))
* Bump spring_version from 7.0.5 to 7.0.6 ([#6008](https://github.com/opensearch-project/security/pull/6008))
