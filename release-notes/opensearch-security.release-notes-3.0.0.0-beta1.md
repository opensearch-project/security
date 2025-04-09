## Version 3.0.0-beta1 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.0.0-beta1

#### Breaking Changes
* Migrate from com.amazon.dlic to org.opensearch.security package ([#5223](https://github.com/opensearch-project/security/pull/5223))
* Remove OpenSSL provider ([#5220](https://github.com/opensearch-project/security/pull/5220))
* Remove whitelist settings in favor of allowlist ([#5224](https://github.com/opensearch-project/security/pull/5224))

#### Bug Fixes
* DlsFlsFilterLeafReader::termVectors implementation causes assertion errors for users with FLS/FM active ([#5243](https://github.com/opensearch-project/security/pull/5243))
* Fixed IllegalArgumentException when building stateful index privileges ([#5217](https://github.com/opensearch-project/security/pull/5217))
* Assume default of v7 models if _meta portion is not present ([#5193](https://github.com/opensearch-project/security/pull/5193))
* Escape pipe character for injected users ([#5175](https://github.com/opensearch-project/security/pull/5175))

#### Maintenance
* Add Shikhar Jain (GH: shikharj05) as a maintainer ([#5252](https://github.com/opensearch-project/security/pull/5252))
* More tests for FLS and field masking ([#5237](https://github.com/opensearch-project/security/pull/5237))
* Bump com.google.errorprone:error_prone_annotations from 2.36.0 to 2.37.0 ([#5245](https://github.com/opensearch-project/security/pull/5245))
* Bump com.netflix.nebula.ospackage from 11.11.1 to 11.11.2 ([#5246](https://github.com/opensearch-project/security/pull/5246))
* Bump org.ow2.asm:asm from 9.7.1 to 9.8 ([#5244](https://github.com/opensearch-project/security/pull/5244))
* Bump org.checkerframework:checker-qual from 3.49.1 to 3.49.2 ([#5247](https://github.com/opensearch-project/security/pull/5247))
* Bump org.mockito:mockito-core from 5.16.1 to 5.17.0 ([#5248](https://github.com/opensearch-project/security/pull/5248))
* Bump open_saml_version from 5.1.3 to 5.1.4 ([#5227](https://github.com/opensearch-project/security/pull/5227))
* Bump com.carrotsearch.randomizedtesting:randomizedtesting-runner from 2.8.2 to 2.8.3 ([#5229](https://github.com/opensearch-project/security/pull/5229))
* Bump open_saml_shib_version from 9.1.3 to 9.1.4 ([#5230](https://github.com/opensearch-project/security/pull/5230))
* Bump com.google.googlejavaformat:google-java-format from 1.25.2 to 1.26.0 ([#5231](https://github.com/opensearch-project/security/pull/5231))
* Bump com.google.guava:guava from 33.4.5-jre to 33.4.6-jre ([#5228](https://github.com/opensearch-project/security/pull/5228))
* Refactor InternalAuditLogTest to use Awaitility ([#5214](https://github.com/opensearch-project/security/pull/5214))
* Improve coverage: Adding tests for ConfigurationRepository class ([#5206](https://github.com/opensearch-project/security/pull/5206))
* Nit: remove java version check for reflection args in build.gradle ([#5218](https://github.com/opensearch-project/security/pull/5218))
* Bump bouncycastle_version from 1.78 to 1.80 ([#5202](https://github.com/opensearch-project/security/pull/5202))
* Update 3.0.0 qualifier from alpha1 to beta1 ([#5207](https://github.com/opensearch-project/security/pull/5207))
* Bump com.google.guava:guava from 33.4.0-jre to 33.4.5-jre ([#5205](https://github.com/opensearch-project/security/pull/5205))
* Bump org.springframework.kafka:spring-kafka-test from 3.3.3 to 3.3.4 ([#5201](https://github.com/opensearch-project/security/pull/5201))
* Bump spring_version from 6.2.4 to 6.2.5 ([#5203](https://github.com/opensearch-project/security/pull/5203))
* Bump ch.qos.logback:logback-classic from 1.5.17 to 1.5.18 ([#5204](https://github.com/opensearch-project/security/pull/5204))
* Add bouncycastle version directly in build.gradle ([#5197](https://github.com/opensearch-project/security/pull/5197))
* Run Security build on image from opensearch-build ([#4966](https://github.com/opensearch-project/security/pull/4966))
* Bump org.eclipse.platform:org.eclipse.equinox.common from 3.19.200 to 3.20.0 ([#5177](https://github.com/opensearch-project/security/pull/5177))

