## Version 2.19.4 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 2.19.4

### Bug Fixes
* Create a WildcardMatcher.NONE when creating a WildcardMatcher with an empty string ([#5694](https://github.com/opensearch-project/security/pull/5694))
* Optimize the Fls/Dls/FieldMasking data structure to only include the concrete indices from the current request ([#5482](https://github.com/opensearch-project/security/pull/5482))
* Ensure that IndexResolverReplacer resolves to indices for RolloverRequests ([#5522](https://github.com/opensearch-project/security/pull/5522))
* Add 'good' as a valid value for plugins.security.restapi.password_score_based_validation_strength ([#5523](https://github.com/opensearch-project/security/pull/5523))
* Use FilterLeafReader based DLS for parent/child queries ([#5538](https://github.com/opensearch-project/security/pull/5538))
* Fixed index resolution for rollover requests ([#5526](https://github.com/opensearch-project/security/pull/5526))
* Fixed TLS endpoint identification by SAN ([#5669](https://github.com/opensearch-project/security/pull/5669))
* Avoid ConcurrentModificationException for User class fields ([#5615](https://github.com/opensearch-project/security/pull/5615))

### Maintenance
* Bump `com.nimbusds:nimbus-jose-jwt:9.48` from 9.48 to 10.0.2 ([#5480](https://github.com/opensearch-project/security/pull/5480))
* Bump `checkstyle` from 10.3.3 to 10.26.1 ([#5480](https://github.com/opensearch-project/security/pull/5480))
* Add tenancy access info to serialized user in threadcontext ([#5519](https://github.com/opensearch-project/security/pull/5519))
* Optimized wildcard matching runtime performance ([#5543](https://github.com/opensearch-project/security/pull/5543))
* Always install demo certs if configured with demo certs ([#5517](https://github.com/opensearch-project/security/pull/5517))
* Bump org.apache.zookeeper:zookeeper from 3.9.3 to 3.9.4 ([#5689](https://github.com/opensearch-project/security/pull/5689))