## 2023-10-18 Version 2.11.0.0

Compatible with OpenSearch 2.11.0

### Enhancements
* Authorization in Rest Layer ([#2753](https://github.com/opensearch-project/security/pull/2753))
* Improve serialization speeds ([#2802](https://github.com/opensearch-project/security/pull/2802))
* Integration tests framework ([#3388](https://github.com/opensearch-project/security/pull/3388))
* Allow for automatic merging of dependabot changes after checks pass ([#3409](https://github.com/opensearch-project/security/pull/3409))
* Support security config updates on the REST API using permission([#3264](https://github.com/opensearch-project/security/pull/3264))
* Expanding Authentication with SecurityRequest Abstraction ([#3430](https://github.com/opensearch-project/security/pull/3430))
* Add early rejection from RestHandler for unauthorized requests ([#3418](https://github.com/opensearch-project/security/pull/3418))

### Bug Fixes
* Refactors reRequestAuthentication to call notifyIpAuthFailureListener before sending the response to the channel ([#3411](https://github.com/opensearch-project/security/pull/3411))
* For read-only tenants filter with allow list ([c3e53e2](https://github.com/opensearch-project/security/commit/c3e53e20a69dc8eb401653594a130c2a4fd4b6bd))

### Maintenance
* Change log message from warning to trace on WWW-Authenticate challenge ([#3446](https://github.com/opensearch-project/security/pull/3446))
* Disable codecov from failing CI if there is an upload issue ([#3379](https://github.com/opensearch-project/security/pull/3379))
* [Refactor] Change HTTP routes for Audit and Config PUT methods   ([#3407](https://github.com/opensearch-project/security/pull/3407))
* Add tracer to Transport ([#3463](https://github.com/opensearch-project/security/pull/3463))
* Adds opensearch trigger bot to discerning merger list to allow automatic merges ([#3481](https://github.com/opensearch-project/security/pull/3481))
* Bump org.apache.camel:camel-xmlsecurity from 3.21.0 to 3.21.1 ([#3436](https://github.com/opensearch-project/security/pull/3436))
* Bump com.github.wnameless.json:json-base from 2.4.2 to 2.4.3 ([#3437](https://github.com/opensearch-project/security/pull/3437))
* Bump org.xerial.snappy:snappy-java from 1.1.10.4 to 1.1.10.5 ([#3438](https://github.com/opensearch-project/security/pull/3438))
* Bump org.ow2.asm:asm from 9.5 to 9.6 ([#3439](https://github.com/opensearch-project/security/pull/3439))
* Bump org.xerial.snappy:snappy-java from 1.1.10.3 to 1.1.10.4 ([#3396](https://github.com/opensearch-project/security/pull/3396))
* Bump com.google.errorprone:error_prone_annotations from 2.21.1 to 2.22.0 ([#3400](https://github.com/opensearch-project/security/pull/3400))
* Bump org.passay:passay from 1.6.3 to 1.6.4 ([#3397](https://github.com/opensearch-project/security/pull/3397))
* Bump org.gradle.test-retry from 1.5.4 to 1.5.5 ([#3399](https://github.com/opensearch-project/security/pull/3399))
* Bump org.springframework:spring-core from 5.3.29 to 5.3.30 ([#3398](https://github.com/opensearch-project/security/pull/3398))
* Bump tibdex/github-app-token from 2.0.0 to 2.1.0 ([#3395](https://github.com/opensearch-project/security/pull/3395))
* Bump org.apache.ws.xmlschema:xmlschema-core from 2.3.0 to 2.3.1 ([#3374](https://github.com/opensearch-project/security/pull/3374))
* Bump apache_cxf_version from 4.0.2 to 4.0.3 ([#3376](https://github.com/opensearch-project/security/pull/3376))
* Bump org.springframework:spring-beans from 5.3.29 to 5.3.30 ([#3375](https://github.com/opensearch-project/security/pull/3375))
* Bump com.github.wnameless.json:json-flattener from 0.16.5 to 0.16.6 ([#3371](https://github.com/opensearch-project/security/pull/3371))
* Bump aws-actions/configure-aws-credentials from 3 to 4 ([#3373](https://github.com/opensearch-project/security/pull/3373))
* Bump org.checkerframework:checker-qual from 3.36.0 to 3.38.0 ([#3378](https://github.com/opensearch-project/security/pull/3378))
* Bump com.nulab-inc:zxcvbn from 1.8.0 to 1.8.2 ([#3357](https://github.com/opensearch-project/security/pull/3357))