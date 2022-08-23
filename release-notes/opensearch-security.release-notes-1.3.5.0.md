## 2022-08-25 Version 1.3.5.0

Compatible with OpenSearch 1.3.5

### Bug fixes

* Triple audit logging fix ([#1996](https://github.com/opensearch-project/security/pull/1996))
* Cluster permissions evaluation logic will now include index_template type action ([#1885](https://github.com/opensearch-project/security/pull/1885))

### Maintenance

* Upgrade jackson-databind from 2.13.2 to 2.13.2.2 to match core's version.properties and upgrade kafka dependencies ([#2000](https://github.com/opensearch-project/security/pull/2000))
