## 2023-01-17 Version 2.5.0.0

Compatible with OpenSearch 2.5.0

### Enhancements
* When excluding fields also exclude the term + .keyword ([#2377](https://github.com/opensearch-project/security/pull/2377))
* Update tool scripts to run in windows ([#2371](https://github.com/opensearch-project/security/pull/2371), [#2379](https://github.com/opensearch-project/security/pull/2379))
* Remove trimming of whitespace when extracting SAML backend roles ([#2381](https://github.com/opensearch-project/security/pull/2381), [#2383](https://github.com/opensearch-project/security/pull/2383))
* Add script for workflow version increment ([#2374](https://github.com/opensearch-project/security/pull/2374), [#2386](https://github.com/opensearch-project/security/pull/2386))

### Bug Fixes
* Changing logging type to give warning for basic auth with no creds ([#2347](https://github.com/opensearch-project/security/pull/2347), [#2364](https://github.com/opensearch-project/security/pull/2364))

### Maintenance
* Upgrade CXF to 3.5.5 to address CVE-2022-46363 ([#2350](https://github.com/opensearch-project/security/pull/2350), [#2357](https://github.com/opensearch-project/security/pull/2357))
