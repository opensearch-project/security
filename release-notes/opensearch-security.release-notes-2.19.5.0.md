## Version 2.19.5 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 2.19.5

### Bug Fixes
* [2.19] Fix issue serializing user to threadcontext when userRequestedTenant is null ([#5925](https://github.com/opensearch-project/security/pull/5925))
* Fix ConcurrentModificationException for SecurityRoles for 2.x ([#5860](https://github.com/opensearch-project/security/pull/5860))

### Infrastructure
* [Backport 2.19] Enable mend remediate to create PRs ([#5784](https://github.com/opensearch-project/security/pull/5784))

### Maintenance
* [2.19] Bump commons-text to 1.15.0 and log4j-core to 2.25.3 ([#5974](https://github.com/opensearch-project/security/pull/5974))
* [Backport 2.19] Bump org.lz4:lz4-java from 1.8.0 to 1.10.1 ([#5970](https://github.com/opensearch-project/security/pull/5970))

### Refactoring
* Use RestRequestFilter.getFilteredRequest to declare sensitive API params ([#5710](https://github.com/opensearch-project/security/pull/5710))