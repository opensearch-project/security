## Version 3.7.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.7.0

### Features

* Introduce API Tokens with cluster and index permissions directly associated with the token ([#5443](https://github.com/opensearch-project/security/pull/5443))
* Add general access field on sharing document to store a single access level for general access ([#6033](https://github.com/opensearch-project/security/pull/6033))
* Support fallback values in DLS/FLS variables ([#6111](https://github.com/opensearch-project/security/pull/6111))

### Enhancements

* Make `opensearch_security.multitenancy.tenants.preferred` configurable dynamically via security config API ([#5986](https://github.com/opensearch-project/security/pull/5986))
* Add salt generation to demo security configuration ([#6022](https://github.com/opensearch-project/security/pull/6022))
* Facilitate FIPS-compliant keystore resolution in test infrastructure ([#6059](https://github.com/opensearch-project/security/pull/6059))
* Support Jackson 3.x release line ([#6078](https://github.com/opensearch-project/security/pull/6078))
* Ensure Netty4Http3ServerTransport uses configured HeaderVerifier and Decompressor instances ([#6108](https://github.com/opensearch-project/security/pull/6108))
* Validate password hashing algorithm for FIPS compliance ([#6126](https://github.com/opensearch-project/security/pull/6126))

### Bug Fixes

* Fix JWT attribute parsing of lists in AbstractHTTPJwtAuthenticator when using `jwks_uri` ([#6058](https://github.com/opensearch-project/security/pull/6058))
* Update RequestContentValidator to only validate fields from request payload, not pre-existing values in security index ([#6061](https://github.com/opensearch-project/security/pull/6061))
* Fix NPE in LDAPAuthorizationBackend when rolesearch is disabled ([#6112](https://github.com/opensearch-project/security/pull/6112))
* Preserve response headers across context restore in SecurityInterceptor ([#6123](https://github.com/opensearch-project/security/pull/6123))
* Fix SSL hot-reload to rebuild trust store instead of validating all CA dates ([#6136](https://github.com/opensearch-project/security/pull/6136))
* Implement skipsDeserialization() in RestoringTransportResponseHandler to fix Arrow Flight stream transport responses ([#6154](https://github.com/opensearch-project/security/pull/6154))

### Infrastructure

* Fix automatic-merges to ensure GitHub workflows run automatically after bot-managed merges ([#6101](https://github.com/opensearch-project/security/pull/6101))
* Wait 45s before health check to resolve Windows plugin install flakiness ([#6125](https://github.com/opensearch-project/security/pull/6125))
* Improve cluster cleanup for in-memory integration test nodes to prevent thread leaks and port conflicts ([#6127](https://github.com/opensearch-project/security/pull/6127))
* Force netty resolution to fix version conflict issues ([#6133](https://github.com/opensearch-project/security/pull/6133))
* Add issues write permission to untriaged label workflow ([#6153](https://github.com/opensearch-project/security/pull/6153))
* Pin actions/github-script to exact commit SHA ([#6157](https://github.com/opensearch-project/security/pull/6157))
* Pin GitHub Actions to commit SHAs for supply chain security ([#6159](https://github.com/opensearch-project/security/pull/6159))

### Documentation

* Add BCFKS keystore generation utilities and documentation ([#6087](https://github.com/opensearch-project/security/pull/6087))
* Introduce an AGENTS.MD file for agentic development guidance ([#6156](https://github.com/opensearch-project/security/pull/6156))

### Maintenance

* Remove unnecessary debug log message for JWT authentication ([#6086](https://github.com/opensearch-project/security/pull/6086))
* Cleanup SafeSerializationUtils to remove unused Guava classes ([#6152](https://github.com/opensearch-project/security/pull/6152))
* Remove passay and Guava BaseEncoding dependencies, replace with JDK equivalents ([#6160](https://github.com/opensearch-project/security/pull/6160))
* Bump OpenSAML to 5.2.2 and remove unused ZooKeeper test dependency ([#6149](https://github.com/opensearch-project/security/pull/6149))

### Refactoring

* Refactor certificate revocation validation for improved testability and diagnostics ([#6042](https://github.com/opensearch-project/security/pull/6042))
* Combine RestApiPrivilegesEvaluator and RestApiAdminPrivilegesEvaluator into RestApiAuthorizationEvaluator ([#6072](https://github.com/opensearch-project/security/pull/6072))
* Elevate tenant to top-level field on resource sharing document ([#6074](https://github.com/opensearch-project/security/pull/6074))
* Simplify `UserAttributes#findUnresolvedAttributes` ([#6122](https://github.com/opensearch-project/security/pull/6122))
* Move logic to reject certain endpoints when using OBO from authenticator to endpoint validator ([#6132](https://github.com/opensearch-project/security/pull/6132))
