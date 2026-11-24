## Version 2.19.8 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 2.19.8

### Bug Fixes

* Block DLS information leakage via global, multi_terms, and nested aggregations with `min_doc_count: 0` ([#6672](https://github.com/opensearch-project/security/pull/6672))
* Honor field-level security visibility in vector APIs and doc-values metadata ([#6723](https://github.com/opensearch-project/security/pull/6723))
* Reject reserved internal identity prefixes in proxy authenticators ([#6670](https://github.com/opensearch-project/security/pull/6670))
