## Version 2.17.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 2.17.0

### Enhancements
* Add `ignore_hosts` config option for auth failure listener ([#4538](https://github.com/opensearch-project/security/pull/4538))
* added API roles for correlationAlerts ([#4689](https://github.com/opensearch-project/security/pull/4689))
* Allow multiple signing keys to be provided ([#4666](https://github.com/opensearch-project/security/pull/4666))
* adding alerting comments security actions to roles.yml ([#4700](https://github.com/opensearch-project/security/pull/4700))
* Permission changes for correlationAlerts ([#4704](https://github.com/opensearch-project/security/pull/4704))

### Bug Fixes
* Addresses a bug with `plugins.security.allow_unsafe_democertificates` setting ([#4603](https://github.com/opensearch-project/security/pull/4603))
* Fix covereage-report workflow ([#4684](https://github.com/opensearch-project/security/pull/4684), [#4683](https://github.com/opensearch-project/security/pull/4683))
* Handle the audit config being null ([#4664](https://github.com/opensearch-project/security/pull/4664))
* Fixes authtoken endpoint ([#4631](https://github.com/opensearch-project/security/pull/4631))
* Fixed READ_ACTIONS required by TermsAggregationEvaluator ([#4607](https://github.com/opensearch-project/security/pull/4607))
* Sort the DNS Names in the SANs ([#4640](https://github.com/opensearch-project/security/pull/4640))

### Maintenance
* Bump com.google.errorprone:error_prone_annotations from 2.30.0 to 2.31.0 ([#4696](https://github.com/opensearch-project/security/pull/4696))
* Bump org.passay:passay from 1.6.4 to 1.6.5 ([#4682](https://github.com/opensearch-project/security/pull/4682))
* Bump spring_version from 5.3.37 to 5.3.39 ([#4661](https://github.com/opensearch-project/security/pull/4661))
* Bump commons-cli:commons-cli from 1.8.0 to 1.9.0 ([#4659](https://github.com/opensearch-project/security/pull/4659))
* Bump org.junit.jupiter:junit-jupiter from 5.10.3 to 5.11.0 ([#4657](https://github.com/opensearch-project/security/pull/4657))
* Bump org.cryptacular:cryptacular from 1.2.6 to 1.2.7 ([#4656](https://github.com/opensearch-project/security/pull/4656))
* Update Gradle to 8.10 ([#4646](https://github.com/opensearch-project/security/pull/4646))
* Bump org.xerial.snappy:snappy-java from 1.1.10.5 to 1.1.10.6 ([#4639](https://github.com/opensearch-project/security/pull/4639))
* Bump com.google.googlejavaformat:google-java-format from 1.22.0 to 1.23.0 ([#4622](https://github.com/opensearch-project/security/pull/4622))
* Increment version to 2.17.0-SNAPSHOT ([#4615](https://github.com/opensearch-project/security/pull/4615))
* Backports PRs with `backport-failed` labels that weren't actually backported ([#4610](https://github.com/opensearch-project/security/pull/4610))
* Bump io.dropwizard.metrics:metrics-core from 4.2.26 to 4.2.27 ([#4660](https://github.com/opensearch-project/security/pull/4660))
* Bump com.netflix.nebula.ospackage from 11.9.1 to 11.10.0 ([#4681](https://github.com/opensearch-project/security/pull/4681))
* Interim build fix for PluginSubject related changes ([#4694](https://github.com/opensearch-project/security/pull/4694))
* Add Nils Bandener (Github: nibix) as a maintainer ([#4673](https://github.com/opensearch-project/security/pull/4673))
* Remove usages of org.apache.logging.log4j.util.Strings ([#4653](https://github.com/opensearch-project/security/pull/4653))
* Update backport section of PR template ([#4625](https://github.com/opensearch-project/security/pull/4625))
* Bump org.checkerframework:checker-qual from 3.45.0 to 3.46.0 ([#4623](https://github.com/opensearch-project/security/pull/4623))
* Refactor security provider instantiation ([#4611](https://github.com/opensearch-project/security/pull/4611))