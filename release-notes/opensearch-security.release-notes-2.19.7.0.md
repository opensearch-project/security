## Version 2.19.7 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 2.19.7

### Enhancements

* Scale legacy alias resolution with bounded indices-lookup access for improved performance on clusters with many aliases ([#6320](https://github.com/opensearch-project/security/pull/6320))

### Bug Fixes

* Fix handling of unsupported HTTP content encodings such as zstd to pass through unmodified ([#6629](https://github.com/opensearch-project/security/pull/6629))
* Fix parent-child query detection across classloaders ([#6478](https://github.com/opensearch-project/security/pull/6478))
* Return the matcher itself when concat collapses to one, preventing inter-node request failures with duplicate `nodes_dn` entries ([#6606](https://github.com/opensearch-project/security/pull/6606))

### Infrastructure

* Guard Eclipse JDT formatter provisioning to spotless tasks and keep P2 mirror on pinned version ([#6462](https://github.com/opensearch-project/security/pull/6462))
* Only provision Eclipse JDT formatter when running a spotless task ([#6453](https://github.com/opensearch-project/security/pull/6453))
