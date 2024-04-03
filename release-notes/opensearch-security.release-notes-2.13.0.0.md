## Version 2.13.0.0

Compatible with OpenSearch 2.13.0

### Enhancements
* Admin role for Query insights plugin ([#4022](https://github.com/opensearch-project/security/pull/4022))
* Add query assistant role and new ml system indices ([#4143](https://github.com/opensearch-project/security/pull/4143))
* Redact sensitive configuration values when retrieving security configuration ([#4028](https://github.com/opensearch-project/security/pull/4028))
* v2.12 update roles.yml with new API for experimental alerting plugin feature ([#4035](https://github.com/opensearch-project/security/pull/4035))
* Add deprecate message that TLSv1 and TLSv1.1 support will be removed in the next major version ([#4083](https://github.com/opensearch-project/security/pull/4083))
* Log password requirement details in demo environment ([#4082](https://github.com/opensearch-project/security/pull/4082))
* Redact sensitive URL parameters from audit logging ([#4070](https://github.com/opensearch-project/security/pull/4070))
* Fix unconsumed parameter exception when authenticating with jwtUrlParameter ([#4065](https://github.com/opensearch-project/security/pull/4065))
* Regenerates root-ca, kirk and esnode certificates to address already expired root ca certificate ([#4066](https://github.com/opensearch-project/security/pull/4066))
* Add exclude_roles configuration parameter to LDAP authorization backend ([#4043](https://github.com/opensearch-project/security/pull/4043))

### Maintenance
* Add exlusion for logback-core to resolve CVE-2023-6378 ([#4050](https://github.com/opensearch-project/security/pull/4050))
* Bump com.netflix.nebula.ospackage from 11.7.0 to 11.8.1 ([#4041](https://github.com/opensearch-project/security/pull/4041), [#4075](https://github.com/opensearch-project/security/pull/4075))
* Bump Wandalen/wretry.action from 1.3.0 to 1.4.10 ([#4042](https://github.com/opensearch-project/security/pull/4042), [#4092](https://github.com/opensearch-project/security/pull/4092), [#4108](https://github.com/opensearch-project/security/pull/4108), [#4135](https://github.com/opensearch-project/security/pull/4135))
* Bump spring_version from 5.3.31 to 5.3.33 ([#4058](https://github.com/opensearch-project/security/pull/4058), [#4131](https://github.com/opensearch-project/security/pull/4131))
* Bump org.scala-lang:scala-library from 2.13.12 to 2.13.13 ([#4076](https://github.com/opensearch-project/security/pull/4076))
* Bump com.google.googlejavaformat:google-java-format from 1.19.1 to 1.21.0 ([#4078](https://github.com/opensearch-project/security/pull/4078), [#4110](https://github.com/opensearch-project/security/pull/4110))
* Bump ch.qos.logback:logback-classic from 1.2.13 to 1.5.3 ([#4091](https://github.com/opensearch-project/security/pull/4091), [#4111](https://github.com/opensearch-project/security/pull/4111))
* Bump com.fasterxml.woodstox:woodstox-core from 6.6.0 to 6.6.1 ([#4093](https://github.com/opensearch-project/security/pull/4093))
* Bump kafka_version from 3.5.1 to 3.7.0 ([#4095](https://github.com/opensearch-project/security/pull/4095))
* Bump jakarta.xml.bind:jakarta.xml.bind-api from 4.0.1 to 4.0.2 ([#4109](https://github.com/opensearch-project/security/pull/4109))
* Bump org.apache.zookeeper:zookeeper from 3.9.1. to 3.9.2 ([#4130](https://github.com/opensearch-project/security/pull/4130))
* Bump org.awaitility:awaitility from 4.2.0 to 4.2.1 ([#4133](https://github.com/opensearch-project/security/pull/4133))
* Bump com.google.errorprone:error_prone_annotations from 2.25.0 to 2.26.1 ([#4132](https://github.com/opensearch-project/security/pull/4132))
