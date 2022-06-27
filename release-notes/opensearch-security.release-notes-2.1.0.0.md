## 2022-06-30 Version 2.1.0.0

Compatible with OpenSearch 2.1.0

### Enhancements
* Delegate to NettyAllocator.getAllocator() for ByteBufAllocator instead of hard-coding PooledByteBufAllocator. ([#1396](https://github.com/opensearch-project/security/pull/1396))
* Tenant Permissions : added the possibility to specify tenants via parameter ([#1813](https://github.com/opensearch-project/security/pull/1813))
* JWT: validate issuer and audience ([#1780](https://github.com/opensearch-project/security/pull/1780), [#1781](https://github.com/opensearch-project/security/pull/1781)) ([#1785](https://github.com/opensearch-project/security/pull/1785))

### Refactoring
* Remove master keywords ([#1886](https://github.com/opensearch-project/security/pull/1886))

### Bug Fix
* Cluster permissions evaluation logic will now include `index_template` type action ([#1885](https://github.com/opensearch-project/security/pull/1885))
* Add missing settings to plugin allowed list ([#1814](https://github.com/opensearch-project/security/pull/1814))
* Updates license headers ([#1829](https://github.com/opensearch-project/security/pull/1829))
* Prevent recursive action groups ([#1868](https://github.com/opensearch-project/security/pull/1868))
* Update `org.springframework:spring-core` to `5.3.20` ([#1850](https://github.com/opensearch-project/security/pull/1850))

### Test Fix
* Bump version to 2.1.0.0 ([#1883](https://github.com/opensearch-project/security/pull/1883))
* ComplianceAuditlogTest to use signal/wait ([#1914](https://github.com/opensearch-project/security/pull/1914))

### Maintenance
* Revert "Bump version to 2.1.0.0 (#1865)" ([#1882](https://github.com/opensearch-project/security/pull/1882))
* Bump version to 2.1.0.0 ([#1865](https://github.com/opensearch-project/security/pull/1865))
* Revert "Bump version to 2.1.0.0 (#1855)" ([#1864](https://github.com/opensearch-project/security/pull/1864))
* Bump version to 2.1.0.0 ([#1855](https://github.com/opensearch-project/security/pull/1855))
* Add suppression for all removal warnings ([#1828](https://github.com/opensearch-project/security/pull/1828))
* Update support link ([#1851](https://github.com/opensearch-project/security/pull/1851))
* Create 2.0.0 release notes ([#1854](https://github.com/opensearch-project/security/pull/1854))
* Switch to standard OpenSearch gradle build ([#1888](https://github.com/opensearch-project/security/pull/1888))
* Fix build break from cluster manager changes ([#1911](https://github.com/opensearch-project/security/pull/1911))
* Update org.apache.zookeeper:zookeeper to 3.7.1 ([#1912](https://github.com/opensearch-project/security/pull/1912))
