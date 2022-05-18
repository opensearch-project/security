## 2022-05-24 Version 2.0.0.0

Compatible with OpenSearch 2.0.0

### Enhancements

* Remove checked-in zip files ([#1774](https://github.com/opensearch-project/security/pull/1774))
* Introduce dfm_empty_overrides_all setting to enable role without dls/fls to override roles with dls/fls ([#1735](https://github.com/opensearch-project/security/pull/1735))
* Add depreciation notice to security tools ([#1756](https://github.com/opensearch-project/security/pull/1756))
* [Practice] Reverting changes ([#1754](https://github.com/opensearch-project/security/pull/1754))
* Renames securityconfig folder to config in bundle step and makes relevant changes ([#1749](https://github.com/opensearch-project/security/pull/1749))
* Updated issue templates from .github. ([#1740](https://github.com/opensearch-project/security/pull/1740))
* Updates Dev guide ([#1590](https://github.com/opensearch-project/security/pull/1590))
* List out test failures in CI log ([#1737](https://github.com/opensearch-project/security/pull/1737))
* Make Git ignore out/ directory ([#1734](https://github.com/opensearch-project/security/pull/1734))
* Fix data-stream name resolution for wild-cards ([#1723](https://github.com/opensearch-project/security/pull/1723))
* Remove support for JDK14 ([#1720](https://github.com/opensearch-project/security/pull/1720))
* Speeding up tests ([#1715](https://github.com/opensearch-project/security/pull/1715))
* Fix min_doc_count handling when using Document Level Security ([#1714](https://github.com/opensearch-project/security/pull/1714))
* Set the mapped security roles of the user so these can be used by the DLS privileges evaluator. Allow security roles to be used for DLS parameter substitution. Fixes opensearch-project/security/#1568 ([#1588](https://github.com/opensearch-project/security/pull/1588))
* Convert Plugin install to only build once ([#1708](https://github.com/opensearch-project/security/pull/1708))
* Upgrade to Gradle 7 ([#1710](https://github.com/opensearch-project/security/pull/1710))
* Move CodeQL into parallel workfow ([#1705](https://github.com/opensearch-project/security/pull/1705))
* Seperate BWC tests into parallel workflow ([#1706](https://github.com/opensearch-project/security/pull/1706))
* Fixes broken test due to unsupported EC using JDK-17 ([#1711](https://github.com/opensearch-project/security/pull/1711))
* Centralize version settings ([#1702](https://github.com/opensearch-project/security/pull/1702))
* Remove TransportClient auth/auth ([#1701](https://github.com/opensearch-project/security/pull/1701))
* Add new code hygiene workflow ([#1699](https://github.com/opensearch-project/security/pull/1699))
* Remove JDK8 from CI ([#1703](https://github.com/opensearch-project/security/pull/1703))
* Add CI check for demo script ([#1690](https://github.com/opensearch-project/security/pull/1690))
* Introduce BWC tests in security plugin ([#1685](https://github.com/opensearch-project/security/pull/1685))
* Correct the step name in CI ([#1683](https://github.com/opensearch-project/security/pull/1683))
* Add support for DLS Term Lookup Queries ([#1541](https://github.com/opensearch-project/security/pull/1541))
* Add Alerting getFindings cluster permission ([#1844](https://github.com/opensearch-project/security/pull/1844))
* Introduce new API _plugins/_security/ssl/certs ([#1841](https://github.com/opensearch-project/security/pull/1841))
* Add default roles for Notifications plugin ([#1847](https://github.com/opensearch-project/security/pull/1847))

### Bug fixes

* Add signal/wait model for TestAuditlogImpl ([#1758](https://github.com/opensearch-project/security/pull/1758))
* Switch to log4j logger ([#1751](https://github.com/opensearch-project/security/pull/1751))
* Remove sleep when waiting for node closure ([#1722](https://github.com/opensearch-project/security/pull/1722))
* Remove explictt dependency on jackson-databind ([#1709](https://github.com/opensearch-project/security/pull/1709))
* Fix break thaat was missed during a merge ([#1707](https://github.com/opensearch-project/security/pull/1707))
* Revert "Replace opensearch class names with opendistro class names during serialization and restore them back during deserialization (#1278)" ([#1691](https://github.com/opensearch-project/security/pull/1691))
* Update to most recent verson of jackson-databind ([#1679](https://github.com/opensearch-project/security/pull/1679))
* Fixed rest status for the replication action failure with DLS/FLS and ([#1677](https://github.com/opensearch-project/security/pull/1677))
* Downgrade Gradle version ([#1661](https://github.com/opensearch-project/security/pull/1661))
* Fix 'openserach' typo in roles.yml ([#1770](https://github.com/opensearch-project/security/pull/1770))

### Maintenance

* Incremented version to 2.0-rc1. ([#1764](https://github.com/opensearch-project/security/pull/1764))
* Upgrade to opensearch 2.0.0 alpha1 ([#1741](https://github.com/opensearch-project/security/pull/1741))
* Upgrade to OpenSearch 2.0.0 ([#1698](https://github.com/opensearch-project/security/pull/1698))
* Move to version 2.0.0.0 ([#1695](https://github.com/opensearch-project/security/pull/1695))
* Generate release notes for 2.0.0 ([#1772](https://github.com/opensearch-project/security/pull/1772))
* Switch from RC1 to the GA of OpenSearch 2.0 ([#1826](https://github.com/opensearch-project/security/pull/1826))
* Updates dependency vulnerabilities versions ([#1806](https://github.com/opensearch-project/security/pull/1806))
* Update org.springframework:spring-core to 5.3.20 ([#1850](https://github.com/opensearch-project/security/pull/1850))
