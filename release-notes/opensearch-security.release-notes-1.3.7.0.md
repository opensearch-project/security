## 2022-12-13 Version 1.3.7.0

Compatible with OpenSearch 1.3.7

### Bug fixes

* Conditionally serialize with ODFE package if min version of node in cluster is less than OS 1.0.0 ([#2268](https://github.com/opensearch-project/security/pull/2268))
* [Backport 1.3] Fix issues with datastream backing indexes ([#2247](https://github.com/opensearch-project/security/pull/2247))

### Maintenance

* [Backport 1.3] Fixes CVE-2022-42920 by forcing bcel version to resovle to 6.6 ([#2304](https://github.com/opensearch-project/security/pull/2304))
* [Backport 1.3] Add plugin install workflow and action  ([#2300](https://github.com/opensearch-project/security/pull/2300))
* Windows build and test support for 1.3 ([#2291](https://github.com/opensearch-project/security/pull/2291))
* 1.3 branch version increment of for jackson to match with core ([#2286](https://github.com/opensearch-project/security/pull/2286))
* Update Dependency Versions:  Woodstox 6.4.0, Scala-lang 2.13.9, Jackson-Databind 2.14.0 ([#2270](https://github.com/opensearch-project/security/pull/2270))
* [Backport 1.3] Add install_demo_configuration Batch script for Windows ([#2273](https://github.com/opensearch-project/security/pull/2273))
* Address CVE-2022-42889 by updating commons-text ([#2241](https://github.com/opensearch-project/security/pull/2241))
