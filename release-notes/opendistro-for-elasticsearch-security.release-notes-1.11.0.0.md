## 2020-10-16 Version 1.11.0.0

Compatible with Elasticsearch version 7.9.1

### Enhancements

* Restrict configured indices access to adminDn only. [#690](https://github.com/opendistro-for-elasticsearch/security/pull/690)

### Bug fixes

* Fix IllegalStateException that is raised when AuditLogImpl.close() is called from ES Bootstrap shutdown hook. [#764](https://github.com/opendistro-for-elasticsearch/security/pull/764)
* Initialize opendistro_role to null in ConfigV6.Kibana and ConfigV7.Kibana so the default value is not persisted in the open distro security config index. [#740](https://github.com/opendistro-for-elasticsearch/security/pull/740)
* Removing newline whitespace from metadata content [#734](https://github.com/opendistro-for-elasticsearch/security/pull/734)

### Maintenance

* Enable alerting in Demo config for plugins security and default alerting roles [#768](https://github.com/opendistro-for-elasticsearch/security/pull/768)
* Generate SHA-512 checksum for opendistro_security .zip only (exclude securityadmin-standalone) [#753](https://github.com/opendistro-for-elasticsearch/security/pull/753)
* Consolidate writeable resource validation check [#752](https://github.com/opendistro-for-elasticsearch/security/pull/752)
* Exclude jakarta.activation-api library from CXF transient dependencies to avoid conflict with jakarata.activation. [#751](https://github.com/opendistro-for-elasticsearch/security/pull/751)
* Upgrade Apache CXF to 3.4.0 [#717](https://github.com/opendistro-for-elasticsearch/security/pull/717)