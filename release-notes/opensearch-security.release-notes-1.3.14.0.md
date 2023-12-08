## 2023-12-08 Version 1.3.14.0

Compatible with OpenSearch 1.3.14

### Bug Fixes

* Prevent OptionalDataException from User data structures ([#3725](https://github.com/opensearch-project/security/pull/3725))

### Enhancement

* Add early rejection from RestHandler for unauthorized requests ([#3675](https://github.com/opensearch-project/security/pull/3675))
* Expanding Authentication with SecurityRequest Abstraction ([#3670](https://github.com/opensearch-project/security/pull/3670))
* Adding minimum viable integration tests framework ([#3649](https://github.com/opensearch-project/security/pull/3649))
* For read-only tenants filter with allow list ([4e962f2](https://github.com/opensearch-project/security/commit/4e962f22a39b22ee4dd7619bfee72544aaae61b0))

### Maintenance

* Update the version of `snappy-java` to 1.1.10.5 ([#3478](https://github.com/opensearch-project/security/pull/3478))
* Update the version of `zookeeper` to 3.9.1, `xmlsec` to 2.3.4, and `jackson-databind` to 2.14.2 ([#3800](https://github.com/opensearch-project/security/pull/3800))
* Adds OpenSearch trigger bot to discerning merger list to allow automatic merges ([#3474](https://github.com/opensearch-project/security/pull/3474))