## 2020-08-28 Version 1.10.0.0

Supported Elasticsearch version 7.9.0

### Enhancements

* Remove cluster monitor check from audit transport check ([#653](https://github.com/opendistro-for-elasticsearch/security/pull/653))
* Enable or disable check for all audit REST and transport categories ([#645](https://github.com/opendistro-for-elasticsearch/security/pull/645))
* Add ability for plugins to inject roles ([#560](https://github.com/opendistro-for-elasticsearch/security/pull/560))

### Bug fixes

* Remove exception details from responses ([#667](https://github.com/opendistro-for-elasticsearch/security/pull/667))
* Adding onelogin loadXML util helper to prevent XXE attacks ([#659](https://github.com/opendistro-for-elasticsearch/security/pull/659))
* Add non-null to store even non-default values in serialization ([#652](https://github.com/opendistro-for-elasticsearch/security/pull/652))
* Refactor opendistro_security_action_trace logger ([#609](https://github.com/opendistro-for-elasticsearch/security/pull/609))
* Fail on invalid rest and transport categories ([#638](https://github.com/opendistro-for-elasticsearch/security/pull/638))
* Correct a typo in the Readme file. ([#607](https://github.com/opendistro-for-elasticsearch/security/pull/607))
* Fix AccessControlException during HTTPSamlAuthenticator initialization. ([#626](https://github.com/opendistro-for-elasticsearch/security/pull/626))
* Remove unnecessary check of remote address for null ([#616](https://github.com/opendistro-for-elasticsearch/security/pull/616))
* Prevent hidden roles from being added via rolesmapping and internalusers API ([#614](https://github.com/opendistro-for-elasticsearch/security/pull/614))


### Maintenance

* Support ES 7.9.0 ([#661](https://github.com/opendistro-for-elasticsearch/security/pull/661))
* Close AuditLog while closing OpenDistroSecurityPlugin and unregister shutdown hook when closing AuditLogImpl. ([#663](https://github.com/opendistro-for-elasticsearch/security/pull/663))
* Fix unit tests failures in HTTPSamlAuthenticatorTest ([#664](https://github.com/opendistro-for-elasticsearch/security/pull/664))
* Add copyright headers for audit classes ([#644](https://github.com/opendistro-for-elasticsearch/security/pull/644))
* Clean up rest and transport header filtering ([#637](https://github.com/opendistro-for-elasticsearch/security/pull/637))
* Upgrade jackson-databind to 2.11.2 ([#618](https://github.com/opendistro-for-elasticsearch/security/pull/618))
