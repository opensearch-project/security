## 2023-04-25 Version 2.7.0.0

Compatible with OpenSearch 2.7.0

### Features

* Dynamic tenancy configurations ([#2607](https://github.com/opensearch-project/security/pull/2607))

### Bug Fixes

* Support multitenancy for the anonymous user ([#2459](https://github.com/opensearch-project/security/pull/2459))
* Fix error message when system index is blocked ([#2525](https://github.com/opensearch-project/security/pull/2525))
* Fix of OpenSSLTest is not using the OpenSSL Provider ([#2301](https://github.com/opensearch-project/security/pull/2301))
* Add chmod 0600 to install_demo_configuration bash script ([#2550](https://github.com/opensearch-project/security/pull/2550))
* Fix SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder" ([#2564](https://github.com/opensearch-project/security/pull/2564))
* Fix lost privileges during auto initializing of the index ([#2498](https://github.com/opensearch-project/security/pull/2498))
* Fix NPE and add additional graceful error handling ([#2687](https://github.com/opensearch-project/security/pull/2687))

### Enhancements

* Clock skew tolerance for oidc token validation ([#2482](https://github.com/opensearch-project/security/pull/2482))
* Adding index template permissions to kibana_server role ([#2503](https://github.com/opensearch-project/security/pull/2503))
* Add a test in order to catch incorrect handling of index parsing during Snapshot Restoration ([#2384](https://github.com/opensearch-project/security/pull/2384))
* Expand Dls Tests for easier verification of functionality ([#2634](https://github.com/opensearch-project/security/pull/2634))
* New system index[.ql-datasources] for ppl/sql datasource configurations ([#2650](https://github.com/opensearch-project/security/pull/2650))
* Allows for configuration of LDAP referral following ([#2135](https://github.com/opensearch-project/security/pull/2135))

### Maintenance

* Update kafka client to 3.4.0 ([#2484](https://github.com/opensearch-project/security/pull/2484))
* Update to gradle 8.0.2 ([#2520](https://github.com/opensearch-project/security/pull/2520))
* XContent Refactor ([#2598](https://github.com/opensearch-project/security/pull/2598))
* Update json-smart to 2.4.10 and update spring-core to 5.3.26 ([#2630](https://github.com/opensearch-project/security/pull/2630))
* Update certs for SecuritySSLReloadCertsActionTests ([#2679](https://github.com/opensearch-project/security/pull/2679))

### Infrastructure

* Add auto github release workflow ([#2450](https://github.com/opensearch-project/security/pull/2450))
* Use correct format for push trigger ([#2474](https://github.com/opensearch-project/security/pull/2474))

### Documentation

* Fix the format of the codeowners file ([#2469](https://github.com/opensearch-project/security/pull/2469))
