## Version 2.16.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 2.16.0

### Enhancements
* Add support for PBKDF2 for password hashing & add support for configuring BCrypt and PBKDF2 ([#4524](https://github.com/opensearch-project/security/pull/4524))
* Use SystemIndexRegistry from core to determine if request contains system indices ([#4471](https://github.com/opensearch-project/security/pull/4471))
* Separated DLS/FLS privilege evaluation from action privilege evaluation ([#4490](https://github.com/opensearch-project/security/pull/4490))
* Update PULL_REQUEST_TEMPLATE to include an API spec change in the checklist. ([#4533](https://github.com/opensearch-project/security/pull/4533))
* Update PATCH API to fail validation if nothing changes ([#4530](https://github.com/opensearch-project/security/pull/4530))
* Refactor InternalUsers REST API test ([#4481](https://github.com/opensearch-project/security/pull/4481))
* Refactor Role Mappings REST API test ([#4450](https://github.com/opensearch-project/security/pull/4450))
* Remove special handling for do_not_fail_on_forbidden on cluster actions ([#4486](https://github.com/opensearch-project/security/pull/4486))
* Add Tenants REST API test and partial fix ([#4166](https://github.com/opensearch-project/security/pull/4166))
* Refactor Roles REST API test and partial fix #4166 ([#4433](https://github.com/opensearch-project/security/pull/4433))
* New algorithm for resolving action groups ([#4448](https://github.com/opensearch-project/security/pull/4448))
* Check block request only if system index ([#4430](https://github.com/opensearch-project/security/pull/4430))
* Replaced uses of SecurityRoles by Set<String> mappedRoles where the SecurityRoles functionality is not needed ([#4432](https://github.com/opensearch-project/security/pull/4432))

### Bug Fixes
* Fixed test failures in FlsAndFieldMaskingTests ([#4548](https://github.com/opensearch-project/security/pull/4548))
* Typo in securityadmin.sh hint ([#4526](https://github.com/opensearch-project/security/pull/4526))
* Fix NPE getting metaFields from mapperService on a close index request ([#4497](https://github.com/opensearch-project/security/pull/4497))
* Fixes flaky integration tests ([#4452](https://github.com/opensearch-project/security/pull/4452))

### Maintenance
* Remove unused dependancy Apache CXF ([#4580](https://github.com/opensearch-project/security/pull/4580))
* Remove unnecessary return statements ([#4558](https://github.com/opensearch-project/security/pull/4558))
* Pass set to SystemIndexRegistry.matchesSystemIndexPattern ([#4569](https://github.com/opensearch-project/security/pull/4569))
* Refactor and update existing ml roles ([#4151](https://github.com/opensearch-project/security/pull/4151))
* Replace JUnit assertEquals() with Hamcrest matchers assertThat() ([#4544](https://github.com/opensearch-project/security/pull/4544))
* Update Gradle to 8.9 ([#4553](https://github.com/opensearch-project/security/pull/4553))
* Bump org.checkerframework:checker-qual from 3.44.0 to 3.45.0 ([#4531](https://github.com/opensearch-project/security/pull/4531))
* Add security analytics threat intel action  ([#4498](https://github.com/opensearch-project/security/pull/4498))
* Bump kafka_version from 3.7.0 to 3.7.1 ([#4501](https://github.com/opensearch-project/security/pull/4501))
* Bump org.junit.jupiter:junit-jupiter from 5.10.2 to 5.10.3 ([#4503](https://github.com/opensearch-project/security/pull/4503))
* Bump com.fasterxml.woodstox:woodstox-core from 6.6.2 to 6.7.0 ([#4483](https://github.com/opensearch-project/security/pull/4483))
* Bump jjwt_version from 0.12.5 to 0.12.6 ([#4484](https://github.com/opensearch-project/security/pull/4484))
* Bump org.eclipse.platform:org.eclipse.core.runtime from 3.31.0 to 3.3.1.100 ([#4467](https://github.com/opensearch-project/security/pull/4467))
* Bump spring_version from 5.3.36 to 5.3.37 ([#4466](https://github.com/opensearch-project/security/pull/4466))
* Update to Gradle 8.8 ([#4459](https://github.com/opensearch-project/security/pull/4459))
