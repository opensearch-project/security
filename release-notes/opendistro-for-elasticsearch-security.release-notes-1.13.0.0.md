## 2021-02-17 Version 1.13.0.0

Compatible with Elasticsearch 7.10.2

### Enhancements

* Using SAML subject_key and roles_key in the HTTPSamlAuthenticator ([#892](https://github.com/opendistro-for-elasticsearch/security/pull/892))
* Support for ES system index ([#946](https://github.com/opendistro-for-elasticsearch/security/pull/946))
* Updating Autheticators to throw RuntimeException on errors ([#505](https://github.com/opendistro-for-elasticsearch/security/pull/505))
* Add security configuration for Kibana Notebooks ([#903](https://github.com/opendistro-for-elasticsearch/security/pull/903))
* Short circuit privilege evaluation for bulk requests without index resolution ([#926](https://github.com/opendistro-for-elasticsearch/security/pull/926))
* Added async search response index to system index list ([#859](https://github.com/opendistro-for-elasticsearch/security/pull/859))

### Bug fixes

* Replace InjectedUser with User during serialization ([#891](https://github.com/opendistro-for-elasticsearch/security/pull/891))
* ConfigUpdateRequest should include only updated CType ([#953](https://github.com/opendistro-for-elasticsearch/security/pull/953))
* Fix AuthCredentials equality ([#876](https://github.com/opendistro-for-elasticsearch/security/pull/876))
* Revert "Using SAML subject_key and roles_key in the HTTPSamlAuthenticator ([#1019](https://github.com/opendistro-for-elasticsearch/security/pull/1019))

### Maintenance

* Pull request intake form (PR template) ([#884](https://github.com/opendistro-for-elasticsearch/security/pull/884))
* Fix typos in template ([#898](https://github.com/opendistro-for-elasticsearch/security/pull/898))
* Upgrade Bouncy Castle to 1.67 ([#910](https://github.com/opendistro-for-elasticsearch/security/pull/910))
* Optimize creating new collection objects in IndexResolverReplacer ([#911](https://github.com/opendistro-for-elasticsearch/security/pull/911))
* Optimize by avoid creating wildcard matchers for every request ([#902](https://github.com/opendistro-for-elasticsearch/security/pull/902))
* Replace writeByte with writeShort in TLSUtilTests ([#927](https://github.com/opendistro-for-elasticsearch/security/pull/927))
* Integrate Github CodeQL Analysis into CI ([#905](https://github.com/opendistro-for-elasticsearch/security/pull/905))
* Rename security plugin artifacts from opendistro_security to opendistro-security ([#966](https://github.com/opendistro-for-elasticsearch/security/pull/966))
* Remove veracode profile and associated config ([#992](https://github.com/opendistro-for-elasticsearch/security/pull/992))
* Try using another port 8088 for running the webhook test ([#999](https://github.com/opendistro-for-elasticsearch/security/pull/999))
* Cleanup single shard request index check ([#993](https://github.com/opendistro-for-elasticsearch/security/pull/993))
* add AD search task permission to ad read access ([#997](https://github.com/opendistro-for-elasticsearch/security/pull/997))
* Change CD workflow to use new staging bucket for artifacts ([#954](https://github.com/opendistro-for-elasticsearch/security/pull/954))
* Refactor Resolved ([#929](https://github.com/opendistro-for-elasticsearch/security/pull/929))
* Combine log messages of no cluster-level permission ([#1002](https://github.com/opendistro-for-elasticsearch/security/pull/1002))
* Support ES 7.10.2 ([#1005](https://github.com/opendistro-for-elasticsearch/security/pull/1005))
* Bump version to 1.13 ([#1004](https://github.com/opendistro-for-elasticsearch/security/pull/1004))
* Cleanup reflection helper and advanced modules enabled / dls fls enabled properties ([#1001](https://github.com/opendistro-for-elasticsearch/security/pull/1001))
* Sample configuration for password strength rules ([#1020](https://github.com/opendistro-for-elasticsearch/security/pull/1020))
* Updating Github actions and files to use main branch. ([#1023](https://github.com/opendistro-for-elasticsearch/security/pull/1023))
* Add the Linux Foundation's Developer Certificate of Origin in pull request template ([#1022](https://github.com/opendistro-for-elasticsearch/security/pull/1022))
* Change the build configuration for deb package and rename the folder of artifacts. ([#1027](https://github.com/opendistro-for-elasticsearch/security/pull/1027))
