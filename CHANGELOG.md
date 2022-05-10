# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Changed 
* [[#1798](https://github.com/opensearch-project/security/pull/1798)] Changed behavior when certificates are reloaded allowing reloading of the same certificate.
* [[#1821](https://github.com/opensearch-project/security/pull/1821)] Changed from release-notes to CHANGELOG.md.

### Removed
* [[#1773](https://github.com/opensearch-project/security/pull/1773)] Removed `advanced_modules_enabled` examples that were outdated.

### Fixed
* [[#1784](https://github.com/opensearch-project/security/pull/1784)] Fixed internal users configuration documentation to include the source role.
* [[#1770](https://github.com/opensearch-project/security/pull/1770)] Fixed incorrect spelling in `cluster:admin/opensearch/ml/stats/nodes` permissions.

### Security

* [[#1806](https://github.com/opensearch-project/security/pull/1806)] Update `org.cryptacular:cryptacular` to `1.2.4`, [CVE-2020-15522].
* [[#1806](https://github.com/opensearch-project/security/pull/1806)] Updated `org.springframework:spring-core` to `5.3.19`, [CVE-2022-22968], [CVE-2022-22965], [CVE-2022-22950].
* [[#1806](https://github.com/opensearch-project/security/pull/1806)] Updated `org.apache.kafka:kafka-clients` to `3.0.0`, [CVE-2020-36518].
* [[#1806](https://github.com/opensearch-project/security/pull/1806)] Updated `org.springframework.kafka:spring-kafka-test` to `2.8.5`, [CVE-2021-45105], [CVE-2021-45046], [CVE-2021-44832], [CVE-2021-44228].

## [2.0.0.0-rc1] - 2022-04-20

### Added

* [[#1609](https://github.com/opensearch-project/security/pull/1609)] Added support for JDK17.
* [[#1710](https://github.com/opensearch-project/security/pull/1710)] Added support for Gradle 7.
* [[#1753](https://github.com/opensearch-project/security/pull/1735)] Added setting `dfm_empty_overrides_all` to prioritize privileges evulation of security roles without Document Level Security restrictions. 
* [[#1508](https://github.com/opensearch-project/security/issues/1508)] Added support for Terms Lookup Queries in Document Level Security, see [the documentation](https://opensearch.org/docs/2.0/security-plugin/access-control/document-level-security/#use-term-level-lookup-queries-tlqs-with-dls) for further details.

### Changed 

* [[#1749](https://github.com/opensearch-project/security/pull/1749)] Changed security configuration placement to be side-by-side with other plugins in the OpenSearch config directory.

### Deprecated

* [[1756](https://github.com/opensearch-project/security/issues/1756)] Deprecated security tools, audit config migrater, hash, security admin, install demo configuration scripts marked as deprecated, see the [deprecation notice](https://github.com/opensearch-project/security/issues/1755) to learn more, replacement plans are still pending.

### Removed

* [[#1718](https://github.com/opensearch-project/security/issues/1718)] Removed support for JDK14. In the future only LTS versions of the JDK will be supported.

### Fixed 

* [[#1751](https://github.com/opensearch-project/security/pull/1751)] Fixed missing log message output in OpenSearch log.

### Security

* [[#1723](https://github.com/opensearch-project/security/pull/1723)] Fixed data exfiltration of index names when wild-card expressions are evalutted. 
* [[#1714](https://github.com/opensearch-project/security/pull/1714)] Fixed data exfiltration of string terms when `min_doc_count` was set to zero.


[unreleased]: https://github.com/opensearch-project/security/compare/2.0.0.0-rc1...HEAD
[2.0.0.0-rc1]: https://github.com/opensearch-project/security/compare/1.3.0.0...2.0.0.0-rc1
[CVE-2020-15522]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15522
[CVE-2022-22968]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22968
[CVE-2022-22965]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965
[CVE-2022-22950]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22950
[CVE-2020-36518]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36518
[CVE-2021-45105]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105
[CVE-2021-45046]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046
[CVE-2021-44832]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44832
[CVE-2021-44228]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228