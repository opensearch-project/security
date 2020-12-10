## 2020-12-14 Version 1.12.0.0

Compatible with Elasticsearch 7.10.0

### Enhancements

* Adding support for SSL dual mode ([#712](https://github.com/opendistro-for-elasticsearch/security/pull/712))
* When replacing .kibana index with multi-tenant index, create index with alias if one already does not exist ([#765](https://github.com/opendistro-for-elasticsearch/security/pull/765))
* Demo Config : Adding AD Indices to system index and creating pre-defined roles ([#776](https://github.com/opendistro-for-elasticsearch/security/pull/776))
* Add user & roles to the thread context  ([#798](https://github.com/opendistro-for-elasticsearch/security/pull/798))
* Security configuration for reporting and notification plugins ([#836](https://github.com/opendistro-for-elasticsearch/security/pull/836))
* Support user injection for transport requests ([#763](https://github.com/opendistro-for-elasticsearch/security/pull/763))
* Support ES 7.10.0 ([#840](https://github.com/opendistro-for-elasticsearch/security/pull/840))
* Support certs with separate Extended Key Usage ([#493](https://github.com/opendistro-for-elasticsearch/security/pull/493))
* Adding requested tenant to the thread context transient info for consumption ([#850](https://github.com/opendistro-for-elasticsearch/security/pull/850))

### Bug fixes

* Fix missing trim when parsing roles in proxy authenticator ([#766](https://github.com/opendistro-for-elasticsearch/security/pull/766))
* Fix empty password issue in upgrade from 6x to 7x ([#816](https://github.com/opendistro-for-elasticsearch/security/pull/816))
* Reject empty password in internal user creation ([#818](https://github.com/opendistro-for-elasticsearch/security/pull/818))
* Use reflection to get reduceOrder, termBytes and format due to java.lang.IllegalAccessError ([#866](https://github.com/opendistro-for-elasticsearch/security/pull/866))
* Fix for java.io.OptionalDataException that is caused by changes to User object after it is put on thread context. ([#869](https://github.com/opendistro-for-elasticsearch/security/pull/869))
* Catch and respond invalid_index_name_exception when an index with invalid name is mentioned ([#865](https://github.com/opendistro-for-elasticsearch/security/pull/865))

### Maintenance

* Create release drafter ([#769](https://github.com/opendistro-for-elasticsearch/security/pull/769))
* Upgrade junit to 4.13.1 ([#835](https://github.com/opendistro-for-elasticsearch/security/pull/835))
* updating static_roles.yml ([#838](https://github.com/opendistro-for-elasticsearch/security/pull/838))
* Security configuration cleanup for static and test resources ([#841](https://github.com/opendistro-for-elasticsearch/security/pull/841))
* Change version to 1.12.0.0 ([#860](https://github.com/opendistro-for-elasticsearch/security/pull/860))
* Upgrade github CD action to using Environment Files ([#862](https://github.com/opendistro-for-elasticsearch/security/pull/862))
* Refactor getUserInfoString ([#864](https://github.com/opendistro-for-elasticsearch/security/pull/864))
* Update 1.12 release notes ([#867](https://github.com/opendistro-for-elasticsearch/security/pull/867))
* Update 1.12 release notes ([#872](https://github.com/opendistro-for-elasticsearch/security/pull/872))
* Use StringJoiner instead of (Immutable)List builder ([#877](https://github.com/opendistro-for-elasticsearch/security/pull/877))
