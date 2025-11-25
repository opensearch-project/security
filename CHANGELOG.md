# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to the [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 3.x]
### Added

### Changed
- Ensure all restHeaders from ActionPlugin.getRestHeaders are carried to threadContext for tracing ([#5396](https://github.com/opensearch-project/security/pull/5396))
- Allow overlap of static and custom security configs, but prefer static ([#5805](https://github.com/opensearch-project/security/pull/5805))

### Features

### Enhancements
- Moved configuration reloading to dedicated thread to improve node stability  ([#5479](https://github.com/opensearch-project/security/pull/5479))
- Makes resource settings dynamic ([#5677](https://github.com/opensearch-project/security/pull/5677))
- [Resource Sharing] Allow multiple sharable resource types in single resource index ([#5713](https://github.com/opensearch-project/security/pull/5713))
- Adding Alerting V2 roles to roles.yml ([#5747](https://github.com/opensearch-project/security/pull/5747))
- add suggest api to ad read access role ([#5754](https://github.com/opensearch-project/security/pull/5754))
- Get list of headersToCopy from core and use getHeader(String headerName) instead of getHeaders() ([#5769](https://github.com/opensearch-project/security/pull/5769))
- [Resource Sharing] Keep track of resource_type on resource sharing document ([#5772](https://github.com/opensearch-project/security/pull/5772))
- Add support for X509 v3 extensions (SAN) for authentication  ([#5701](https://github.com/opensearch-project/security/pull/5701))
- [Resource Sharing] Requires default_owner for resource/migrate API ([#5789](https://github.com/opensearch-project/security/pull/5789))

* Create a mechanism for plugins to explicitly declare actions they need to perform with their assigned PluginSubject ([#5341](https://github.com/opensearch-project/security/pull/5341))
* Moves OpenSAML jars to a Shadow Jar configuration to facilitate its use in FIPS enabled environments ([#5400](https://github.com/opensearch-project/security/pull/5404))
* Replaced the standard distribution of BouncyCastle with BC-FIPS ([#5439](https://github.com/opensearch-project/security/pull/5439))
* Introduce API Tokens with `cluster_permissions` and `index_permissions` directly associated with the token ([#5443](https://github.com/opensearch-project/security/pull/5443))
* Introduced setting `plugins.security.privileges_evaluation.precomputed_privileges.enabled` ([#5465](https://github.com/opensearch-project/security/pull/5465))
* Optimized wildcard matching runtime performance ([#5470](https://github.com/opensearch-project/security/pull/5470))
* Optimized performance for construction of internal action privileges data structure  ([#5470](https://github.com/opensearch-project/security/pull/5470))

### Bug Fixes
- Create a WildcardMatcher.NONE when creating a WildcardMatcher with an empty string ([#5694](https://github.com/opensearch-project/security/pull/5694))
- Improve array validator to also check for blank string in addition to null ([#5714](https://github.com/opensearch-project/security/pull/5714))
- Use RestRequestFilter.getFilteredRequest to declare sensitive API params ([#5710](https://github.com/opensearch-project/security/pull/5710))
- Fix deprecated SSL transport settings in demo certificates ([#5723](https://github.com/opensearch-project/security/pull/5723))
- Updates DlsFlsValveImpl condition to return true if request is internal and not a protected resource request ([#5721](https://github.com/opensearch-project/security/pull/5721))
- [Performance] Call AdminDns.isAdmin once per request ([#5752](https://github.com/opensearch-project/security/pull/5752))
- Update operations on `.kibana` system index now work correctly with Dashboards multi tenancy enabled. ([#5778](https://github.com/opensearch-project/security/pull/5778))

### Refactoring
- [Resource Sharing] Make migrate api require default access level to be supplied and updates documentations + tests ([#5717](https://github.com/opensearch-project/security/pull/5717))
- [Resource Sharing] Removes share and revoke java APIs ([#5718](https://github.com/opensearch-project/security/pull/5718))
- Fix build failure in SecurityFilterTests ([#5736](https://github.com/opensearch-project/security/pull/5736))
- [Resource Sharing]Refactor ResourceProvider to an interface and other ResourceSharing refactors ([#5755](https://github.com/opensearch-project/security/pull/5755))
- Replace AccessController and remove restriction on word Extension ([#5750](https://github.com/opensearch-project/security/pull/5750))
- Add security provider earlier in bootstrap process ([#5749](https://github.com/opensearch-project/security/pull/5749))
- [GRPC] Fix compilation errors from core protobuf version bump to 0.23.0 ([#5763](https://github.com/opensearch-project/security/pull/5763))
- Modularized PrivilegesEvaluator ([#5791](https://github.com/opensearch-project/security/pull/5791))
- [Resource Sharing] Adds post support for update sharing info API ([#5799](https://github.com/opensearch-project/security/pull/5799))
- Cleaned up use of PrivilegesEvaluatorResponse ([#5804](https://github.com/opensearch-project/security/pull/5804))

### Maintenance
- Bump `org.junit.jupiter:junit-jupiter` from 5.13.4 to 5.14.1 ([#5678](https://github.com/opensearch-project/security/pull/5678), [#5764](https://github.com/opensearch-project/security/pull/5764))
- Bump `ch.qos.logback:logback-classic` from 1.5.18 to 1.5.20 ([#5680](https://github.com/opensearch-project/security/pull/5680), [#5724](https://github.com/opensearch-project/security/pull/5724))
- Bump `org.scala-lang:scala-library` from 2.13.16 to 2.13.18 ([#5682](https://github.com/opensearch-project/security/pull/5682), [#5809](https://github.com/opensearch-project/security/pull/5809))
- Bump `kafka_version` from 4.0.0 to 4.1.1 ([#5613](https://github.com/opensearch-project/security/pull/5613), [#5806](https://github.com/opensearch-project/security/pull/5806))
- Bump `org.gradle.test-retry` from 1.6.2 to 1.6.4 ([#5706](https://github.com/opensearch-project/security/pull/5706))
- Bump `org.checkerframework:checker-qual` from 3.51.0 to 3.51.1 ([#5705](https://github.com/opensearch-project/security/pull/5705))
- Bump `org.ow2.asm:asm` from 9.8 to 9.9 ([#5707](https://github.com/opensearch-project/security/pull/5707))
- Bump `stefanzweifel/git-auto-commit-action` from 6 to 7 ([#5704](https://github.com/opensearch-project/security/pull/5704))
- Bump `net.bytebuddy:byte-buddy` from 1.17.7 to 1.17.8 ([#5703](https://github.com/opensearch-project/security/pull/5703))
- Bump `derek-ho/start-opensearch` from 7 to 9 ([#5630](https://github.com/opensearch-project/security/pull/5630), [#5679](https://github.com/opensearch-project/security/pull/5679))
- Bump `github/codeql-action` from 3 to 4 ([#5702](https://github.com/opensearch-project/security/pull/5702))
- Bump `com.github.spotbugs` from 6.4.2 to 6.4.4 ([#5727](https://github.com/opensearch-project/security/pull/5727))
- Bump `com.autonomousapps.build-health` from 3.0.4 to 3.3.0 ([#5726](https://github.com/opensearch-project/security/pull/5726), [#5744](https://github.com/opensearch-project/security/pull/5744))
- Bump `spring_version` from 6.2.11 to 6.2.14 ([#5725](https://github.com/opensearch-project/security/pull/5725), [#5808](https://github.com/opensearch-project/security/pull/5808))
- Bump `org.springframework.kafka:spring-kafka-test` from 4.0.0-M5 to 4.0.0-RC1 ([#5742](https://github.com/opensearch-project/security/pull/5742))
- Bump `com.google.errorprone:error_prone_annotations` from 2.42.0 to 2.44.0 ([#5743](https://github.com/opensearch-project/security/pull/5743), [#5779](https://github.com/opensearch-project/security/pull/5779))
- Bump `actions/upload-artifact` from 4 to 5 ([#5740](https://github.com/opensearch-project/security/pull/5740))
- Bump `actions/download-artifact` from 5 to 6 ([#5739](https://github.com/opensearch-project/security/pull/5739))
- Bump `com.google.googlejavaformat:google-java-format` from 1.28.0 to 1.32.0 ([#5741](https://github.com/opensearch-project/security/pull/5741), [#5765](https://github.com/opensearch-project/security/pull/5765), [#5811](https://github.com/opensearch-project/security/pull/5811))
- Bump `com.jayway.jsonpath:json-path` from 2.9.0 to 2.10.0 ([#5767](https://github.com/opensearch-project/security/pull/5767))
- Bump `org.apache.ws.xmlschema:xmlschema-core` from 2.3.1 to 2.3.2 ([#5781](https://github.com/opensearch-project/security/pull/5781))
- Bump `commons-io:commons-io` from 2.20.0 to 2.21.0 ([#5780](https://github.com/opensearch-project/security/pull/5780))
- Bump `com.nimbusds:nimbus-jose-jwt` from 10.5 to 10.6 ([#5782](https://github.com/opensearch-project/security/pull/5782))
- Upgrade to gradle 9.2 and run CI with JDK 25 ([#5786](https://github.com/opensearch-project/security/pull/5786))
- Bump `commons-validator:commons-validator` from 1.10.0 to 1.10.1 ([#5807](https://github.com/opensearch-project/security/pull/5807))
- Bump `actions/checkout` from 5 to 6 ([#5810](https://github.com/opensearch-project/security/pull/5810))

### Documentation

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.3...main
