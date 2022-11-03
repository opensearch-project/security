## 2022-11-10 Version 2.4.0.0

Compatible with OpenSearch 2.4.0

### Enhancements
* Add install_demo_configuration Batch script for Windows ([#2161](https://github.com/opensearch-project/security/pull/2161)[#2203](https://github.com/opensearch-project/security/commit/51a286230f5ba1829dd7e62af1b626540eee3600)
* Add CI for Windows and MacOS platforms ([#2190](https://github.com/opensearch-project/security/pull/2190)[#2205](https://github.com/opensearch-project/security/pull/2205))
* Make ldap pool period and idle time configurable ([#2091](https://github.com/opensearch-project/security/commit/edd9f49e161739fe26f2d3652121e6c187636b79)[#2097](https://github.com/opensearch-project/security/pull/2097))
* Allow custom LDAP return attributes ([#2093](https://github.com/opensearch-project/security/pull/2093)[#2110](https://github.com/opensearch-project/security/pull/2110))
* Add bcpkix-jdk15on runtimeOnly dependency to read keys with bouncycastle ([#2191](https://github.com/opensearch-project/security/pull/2191)[#2200](https://github.com/opensearch-project/security/pull/2200))

### Bug Fixes
* Point in time API security changes ([#2094](https://github.com/opensearch-project/security/pull/2094)[#2223](https://github.com/opensearch-project/security/pull/2223))
* Fix windows encoding issues ([#2206](https://github.com/opensearch-project/security/pull/2206)[#2218](https://github.com/opensearch-project/security/pull/2218))

### Maintenance
* Add groupId = org.opensearch.plugin ([#2158](https://github.com/opensearch-project/security/pull/2158)[#2185](https://github.com/opensearch-project/security/pull/2185))
* Roles yml changes for security-analytics plugin ([#2192](https://github.com/opensearch-project/security/pull/2192)[#2225](https://github.com/opensearch-project/security/pull/2225))
* Upgrade Kafka Client to 3.0.2 ([#2123](https://github.com/opensearch-project/security/pull/2123)[#2126](https://github.com/opensearch-project/security/pull/2126))
* Log deprecation message on legacy ldap pool settings ([#2099](https://github.com/opensearch-project/security/pull/2099)[#2147](https://github.com/opensearch-project/security/pull/2147))
* Address CVE-2022-42889 by updating commons-text ([#2177](https://github.com/opensearch-project/security/pull/2177)[#2186](https://github.com/opensearch-project/security/pull/2186))
* Patch bump for scala dependency ([#2163](https://github.com/opensearch-project/security/pull/2163)[#2187](https://github.com/opensearch-project/security/commit/1f3de6a064696eb098749a340853c4f6af4c619f))
* Woodstox Version Bump to 6.4.0 ([#2197](https://github.com/opensearch-project/security/pull/2197)[#2199](https://github.com/opensearch-project/security/pull/2199))
