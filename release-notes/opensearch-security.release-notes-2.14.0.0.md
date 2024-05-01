## Version 2.14.0.0

Compatible with OpenSearch 2.14.0

### Enhancements
* Check for and perform upgrades on security configurations ([#4251](https://github.com/opensearch-project/security/pull/4251))
* Replace bouncy castle blake2b ([#4284](https://github.com/opensearch-project/security/pull/4284))
* Adds saml auth header to differentiate saml requests and prevents auto login as anonymous user when basic authentication fails ([#4228](https://github.com/opensearch-project/security/pull/4228))
* Dynamic sign in options ([#4137](https://github.com/opensearch-project/security/pull/4137))
* Add index permissions for query insights exporters ([#4231](https://github.com/opensearch-project/security/pull/4231))
* Add new stop words system index ([#4181](https://github.com/opensearch-project/security/pull/4181))
* Switch to built-in security transports from core ([#4119](https://github.com/opensearch-project/security/pull/4119)) ([#4174](https://github.com/opensearch-project/security/pull/4174)) ([#4187](https://github.com/opensearch-project/security/pull/4187))
* System index permission grants reading access to documents in the index ([#4291](https://github.com/opensearch-project/security/pull/4291))
* Improve cluster initialization reliability ([#4002](https://github.com/opensearch-project/security/pull/4002)) ([#4256](https://github.com/opensearch-project/security/pull/4256))

### Bug Fixes
* Ensure that challenge response contains body ([#4268](https://github.com/opensearch-project/security/pull/4268))
* Add logging for audit log that are unable to saving the request body ([#4272](https://github.com/opensearch-project/security/pull/4272))
* Use predictable serialization logic for transport headers ([#4288](https://github.com/opensearch-project/security/pull/4288))
* Update Log4JSink Default from sgaudit to audit and add test for default values ([#4155](https://github.com/opensearch-project/security/pull/4155))
* Remove Pom task dependencies rewrite ([#4178](https://github.com/opensearch-project/security/pull/4178)) ([#4186](https://github.com/opensearch-project/security/pull/4186))
* Misc changes for tests ([#4184](https://github.com/opensearch-project/security/pull/4184))
* Add simple roles mapping integ test to test mapping of backend role to role ([#4176](https://github.com/opensearch-project/security/pull/4176))

### Maintenance
* Add getProperty.org.bouncycastle.ec.max_f2m_field_size to plugin-security.policy ([#4270](https://github.com/opensearch-project/security/pull/4270))
* Add getProperty.org.bouncycastle.pkcs12.default to plugin-security.policy ([#4266](https://github.com/opensearch-project/security/pull/4266))
* Bump apache_cxf_version from 4.0.3 to 4.0.4 ([#4287](https://github.com/opensearch-project/security/pull/4287))
* Bump ch.qos.logback:logback-classic from 1.5.3 to 1.5.5 ([#4248](https://github.com/opensearch-project/security/pull/4248))
* Bump codecov/codecov-action from v3 to v4 ([#4237](https://github.com/opensearch-project/security/pull/4237))
* Bump com.fasterxml.woodstox:woodstox-core from 6.6.1 to 6.6.2 ([#4195](https://github.com/opensearch-project/security/pull/4195))
* Bump com.google.googlejavaformat:google-java-format from 1.21.0 to 1.22.0 ([#4220](https://github.com/opensearch-project/security/pull/4220))
* Bump commons-io:commons-io from 2.15.1 to 2.16.1 ([#4196](https://github.com/opensearch-project/security/pull/4196)) ([#4246](https://github.com/opensearch-project/security/pull/4246))
* Bump com.nulab-inc:zxcvbn from 1.8.2 to 1.9.0 ([#4219](https://github.com/opensearch-project/security/pull/4219))
* Bump io.dropwizard.metrics:metrics-core from 4.2.15 to 4.2.25 ([#4193](https://github.com/opensearch-project/security/pull/4193)) ([#4197](https://github.com/opensearch-project/security/pull/4197))
* Bump net.shibboleth.utilities:java-support from 8.4.1 to 8.4.2 ([#4245](https://github.com/opensearch-project/security/pull/4245))
* Bump spring_version from 5.3.33 to 5.3.34 ([#4250](https://github.com/opensearch-project/security/pull/4250))
* Bump Wandalen/wretry.action from 1.4.10 to 3.3.0 ([#4167](https://github.com/opensearch-project/security/pull/4167)) ([#4198](https://github.com/opensearch-project/security/pull/4198)) ([#4221](https://github.com/opensearch-project/security/pull/4221)) ([#4247](https://github.com/opensearch-project/security/pull/4247))
* Bump open_saml_version from 4.3.0 to 4.3.2 ([#4303](https://github.com/opensearch-project/security/pull/4303)) ([#4239](https://github.com/opensearch-project/security/pull/4239))
