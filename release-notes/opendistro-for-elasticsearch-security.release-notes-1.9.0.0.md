## 2020-06-29 Version 1.9.0.0

Supported Elasticsearch version 7.8.0

### Enhancements
- Added support for Elasticsearch 7.8.0 ([#516](https://github.com/opendistro-for-elasticsearch/security/pull/516))
- Allow superadmin to update/delete hidden resources ([#513](https://github.com/opendistro-for-elasticsearch/security/pull/513))
- Added metadata_content to SAML config ([#477](https://github.com/opendistro-for-elasticsearch/security/pull/477), [#495](https://github.com/opendistro-for-elasticsearch/security/pull/495))
- Implemented put if absent behavior for security config ([#402](https://github.com/opendistro-for-elasticsearch/security/pull/402))

### Bug fixes
- Removed the faulty index exists check and have more predictable behavior ([#517](https://github.com/opendistro-for-elasticsearch/security/pull/517))
- Avoid using Basic Authorization header as JWT token ([#501](https://github.com/opendistro-for-elasticsearch/security/pull/501))
- Granted access to all packages under com.sun.jndi ([#494](https://github.com/opendistro-for-elasticsearch/security/pull/494))
- Prevented users from mapping to hidden/reserved opendistro_security_roles ([#486](https://github.com/opendistro-for-elasticsearch/security/pull/486))
- Checked for substitute permissions before attempting to use SafeObjectOutputStream ([#478](https://github.com/opendistro-for-elasticsearch/security/pull/478))

### Maintenance
- Updated Maven endpoint URL for deployment ([#519](https://github.com/opendistro-for-elasticsearch/security/pull/519))
- Avoid using reflection to instantiate OpenDistroSecurityFlsDlsIndexSearcherWrapper ([#511](https://github.com/opendistro-for-elasticsearch/security/pull/511))
- Bumped Jackson-databind version ([#509](https://github.com/opendistro-for-elasticsearch/security/pull/509))
- Refactored salt from compliance config into Salt class ([#506](https://github.com/opendistro-for-elasticsearch/security/pull/506))
- Fixed typo in DefaultOpenDistroSecurityKeyStore.java ([#502](https://github.com/opendistro-for-elasticsearch/security/pull/502))
- Refactored to use indexing operation listener for every index module call ([#491](https://github.com/opendistro-for-elasticsearch/security/pull/491))
- Moved compliance ignore users from audit config to compliance config ([#484](https://github.com/opendistro-for-elasticsearch/security/pull/484))
- Removed immutable indices from compliance config ([#483](https://github.com/opendistro-for-elasticsearch/security/pull/483))
- Updated CD workflow to publish artifacts to maven central ([#481](https://github.com/opendistro-for-elasticsearch/security/pull/481))
- Refactored Base64Helper class ([#468](https://github.com/opendistro-for-elasticsearch/security/pull/468))
- Refactored WildcardMatcher ([#458](https://github.com/opendistro-for-elasticsearch/security/pull/458))
