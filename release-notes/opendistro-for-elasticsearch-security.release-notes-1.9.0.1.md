## 2020-07-30 Version 1.9.0.1

### Enhancements
- Hot reloading audit configuration ([#409](https://github.com/opendistro-for-elasticsearch/security/pull/409))
- Add configuration for REST API whitelisting ([#520](https://github.com/opendistro-for-elasticsearch/security/pull/520))
- Implement ability to configure readonly fields for audit configuration ([#559](https://github.com/opendistro-for-elasticsearch/security/pull/559))
- Decrypt SAML assertions ([#539](https://github.com/opendistro-for-elasticsearch/security/pull/539))
- Add REST API method to audit logging ([#589](https://github.com/opendistro-for-elasticsearch/security/pull/589))
- Log index event requests on transport layer ([#588](https://github.com/opendistro-for-elasticsearch/security/pull/588))
- Added kibana attribute to security config which will be used by tenantinfo api. ([#514](https://github.com/opendistro-for-elasticsearch/security/pull/514))
- Log granted privileges on REST layer if user has access to opendistro APIs ([#594](https://github.com/opendistro-for-elasticsearch/security/pull/594))

### Bug fixes
- Fix broken link to security configuration page ([#558](https://github.com/opendistro-for-elasticsearch/security/pull/558))
- Make sure Internal users API supports adding reserved opendistrosecurityroles 
 (by superuser). Do not filter out reserved roles in the InternalUsersModelV7 ([#556](https://github.com/opendistro-for-elasticsearch/security/pull/556))
- Removing hidden/reserved roles added via roles mapping ([#586](https://github.com/opendistro-for-elasticsearch/security/pull/586))

### Maintenance
- Refactoring: moved getSettingAsSet() method and DEFAULT_DISABLED_CATEGORIES from AuditConfig to ConfigConstants. ([#543](https://github.com/opendistro-for-elasticsearch/security/pull/543))
- Introduced method to construct AuditCategory EnumSet from Settings ([#543](https://github.com/opendistro-for-elasticsearch/security/pull/543))
- Use Jackson to serialize and de-serialize audit configuration ([#542](https://github.com/opendistro-for-elasticsearch/security/pull/542))
- Support "true" and "false" String to boolean conversion in DefaultObjectMapper.getOrDefault() ([#548](https://github.com/opendistro-for-elasticsearch/security/pull/548))
- Removing static ILM action groups ([#552](https://github.com/opendistro-for-elasticsearch/security/pull/552))
- Fix failing NodesDnApiTest#testNodesDnApi ([#568](https://github.com/opendistro-for-elasticsearch/security/pull/568))
- Upgrade Apache CXF to 3.2.14 ([#577](https://github.com/opendistro-for-elasticsearch/security/pull/577))
- Upgrade Apache Kafka Client to 2.5.0 ([#584](https://github.com/opendistro-for-elasticsearch/security/pull/584))
- Upgrade Onelogin Java SAML to 2.5.0 ([#585](https://github.com/opendistro-for-elasticsearch/security/pull/585))
- Upgrade Bouncy Castle to 1.66 ([#603](https://github.com/opendistro-for-elasticsearch/security/pull/603))
- Upgrade OpenSAML SAML Provider Implementations to 3.4.5 ([#604](https://github.com/opendistro-for-elasticsearch/security/pull/604))
