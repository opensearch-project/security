## 2020-12-14 Version 1.12.0.0

Compatible with Elasticsearch 7.10.0

## Enhancements

* Adding support for SSL dual mode [#712](https://github.com/opendistro-for-elasticsearch/security/pull/712)
* When replacing .kibana index with multi-tenant index, create index with alias if one already does not exist [#765](https://github.com/opendistro-for-elasticsearch/security/pull/765)
* Demo Config : Adding AD Indices to system index and creating pre-defined roles [#776](https://github.com/opendistro-for-elasticsearch/security/pull/776)
* Add user & roles to the thread context  [#798](https://github.com/opendistro-for-elasticsearch/security/pull/798)
* Security configuration for reporting and notification plugins [#836](https://github.com/opendistro-for-elasticsearch/security/pull/836)
* Support user injection for transport requests [#763](https://github.com/opendistro-for-elasticsearch/security/pull/763)
* Support ES 7.10.0 [#840](https://github.com/opendistro-for-elasticsearch/security/pull/840)

## Bug fixes

* Fix missing trim when parsing roles in proxy authenticator [#766](https://github.com/opendistro-for-elasticsearch/security/pull/766)
* Fix empty password issue in upgrade from 6x to 7x [#816](https://github.com/opendistro-for-elasticsearch/security/pull/816)

## Maintenance

* Create release drafter [#769](https://github.com/opendistro-for-elasticsearch/security/pull/769)
* Upgrade junit to 4.13.1 [#835](https://github.com/opendistro-for-elasticsearch/security/pull/835)
* updating static_roles.yml [#838](https://github.com/opendistro-for-elasticsearch/security/pull/838)
* Security configuration cleanup for static and test resources [#841](https://github.com/opendistro-for-elasticsearch/security/pull/841)
