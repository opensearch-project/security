## 2021-08-31 Version 1.0.1.0

Compatible with OpenSearch 1.0.0

### Bug fixes

* Return HTTP 409 if get parallel put request ([#1158](https://github.com/opensearch-project/security/pull/1158))
* Add validation for null array DataType ([#1157](https://github.com/opensearch-project/security/pull/1157))
* Add support for ResolveIndexAction handling ([#1312](https://github.com/opensearch-project/security/pull/1312))
* Fix LDAP authentication when using StartTLS ([#1415](https://github.com/opensearch-project/security/pull/1415))
* Fix index permissions for negative lookahead and negated regex index patterns ([#1300](https://github.com/opensearch-project/security/pull/1300))

### Maintenance

* Fix maven build ${version} deprecation warning ([#1209](https://github.com/opensearch-project/security/pull/1209))
* Fix race condition on async test for PR #1158 ([#1331](https://github.com/opensearch-project/security/pull/1331))
* Build OpenSearch in CD workflow in order to build security plugin ([#1364](https://github.com/opensearch-project/security/pull/1364))
* Update checkNullElementsInArray() unit test to check both error message and error code instead of only checking the error code ([#1370](https://github.com/opensearch-project/security/pull/1370))
* Add themed logo to README ([#1333](https://github.com/opensearch-project/security/pull/1333))
* Checkout OpenSearch after Cache in CD ([#1410](https://github.com/opensearch-project/security/pull/1410))
* Address follow up comments for PR #1172 ([#1224](https://github.com/opensearch-project/security/pull/1224))
* Upgrade CXF to v3.4.4 ([#1412](https://github.com/opensearch-project/security/pull/1412))
* Bump version to 1.0.1.0 ([#1418](https://github.com/opensearch-project/security/pull/1418))
