## 2022-03-15 Version 1.3.0.0

Compatible with OpenSearch 1.3.0

### Enhancements

* Adds CI support for Java 8, 11 and 14 ([#1580](https://github.com/opensearch-project/security/pull/1580))
* Updates the test retry-count to give flaky tests more chances to pass ([#1601](https://github.com/opensearch-project/security/pull/1601))
* Adds support for OPENSEARCH_JAVA_HOME ([#1603](https://github.com/opensearch-project/security/pull/1603))
* Adds auto delete workflow for backport branches ([#1604](https://github.com/opensearch-project/security/pull/1604))
* Create the plugin-descriptor programmatically ([#1623](https://github.com/opensearch-project/security/pull/1623))
* Add test to make sure exception causes aren't sent to callers ([#1639](https://github.com/opensearch-project/security/pull/1639))
* Switch gradle to info logging for improved test debugging ([#1646](https://github.com/opensearch-project/security/pull/1646))
* Remove artifact step from CI workflow ([#1645](https://github.com/opensearch-project/security/pull/1645))
* Adds ssl script ([#1530](https://github.com/opensearch-project/security/pull/1530))
* Adds Java-17 to CI matrix ([#1609](https://github.com/opensearch-project/security/pull/1609))
* Reverts ssl script PR ([#1637](https://github.com/opensearch-project/security/pull/1637))
* Remove java17 from 1.3 build matrix ([#1668](https://github.com/opensearch-project/security/pull/1668))

### Bug fixes

* Bumps JJWT version ([#1589](https://github.com/opensearch-project/security/pull/1589))
* Updates backport workflow with custom branch and github app ([#1597](https://github.com/opensearch-project/security/pull/1597))
* Always run checks on PRs ([#1615](https://github.com/opensearch-project/security/pull/1615))
* Adds 'opens' command-line argument for java.io libraries to unblock build ([#1616](https://github.com/opensearch-project/security/pull/1616))
* Adds jacoco report and pass the location to codecov ([#1617](https://github.com/opensearch-project/security/pull/1617))
* Fixes the settings of roles_separator ([#1618](https://github.com/opensearch-project/security/pull/1618))
* Use standard opensearch.version property ([#1622](https://github.com/opensearch-project/security/pull/1622))


### Maintenance

* Updates bug template ([#1582](https://github.com/opensearch-project/security/pull/1582))
* Updates jackson-databind library version ([#1584](https://github.com/opensearch-project/security/pull/1584))
* Upgrades Kafka version ([#1598](https://github.com/opensearch-project/security/pull/1598))
* Upgrades Guava version ([#1594](https://github.com/opensearch-project/security/pull/1594))
* Update maintainers list ([#1607](https://github.com/opensearch-project/security/pull/1607))
* Exclude velocity 1.7 from OpenSAML dependency ([#1606](https://github.com/opensearch-project/security/pull/1606))
* Migrate build system to gradle ([#1592](https://github.com/opensearch-project/security/pull/1592))
* Updates documentation for practices for maintainers ([#1611](https://github.com/opensearch-project/security/pull/1611))
* Remove jcenter repository ([#1625](https://github.com/opensearch-project/security/pull/1625))
* Remove '-SNAPSHOT' from opensearch.version in plugin descriptor ([#1634](https://github.com/opensearch-project/security/pull/1634))
* Add git ignore for VScode IDE settings ([#1629](https://github.com/opensearch-project/security/pull/1629))
* Remove netty-tcnative dependency to unblock security plugin build on ARM64 ([#1649](https://github.com/opensearch-project/security/pull/1649))
* Add plugin-descriptor.properties to .gitignore ([#1651](https://github.com/opensearch-project/security/pull/1651))
* Removes Github DCO action as it is replaced by Github app ([1657](https://github.com/opensearch-project/security/pull/1657))
* Configure ML reserved roles and system indices ([#1662](https://github.com/opensearch-project/security/pull/1662))
* Release Notes for 1.3.0.0 ([#1671](https://github.com/opensearch-project/security/pull/1671))
