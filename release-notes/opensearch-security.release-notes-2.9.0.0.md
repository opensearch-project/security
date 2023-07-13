## 2023-07-18 Version 2.9.0.0

Compatible with OpenSearch 2.9.0

### Enhancements

* Use boucycastle PEM reader instead of reg expression ([#2877](https://github.com/opensearch-project/security/pull/2877))
* Adding field level security test cases for FlatFields ([#2876](https://github.com/opensearch-project/security/pull/2876)) ([#2893](https://github.com/opensearch-project/security/pull/2893))
* Add password message to /dashboardsinfo endpoint ([#2949](https://github.com/opensearch-project/security/pull/2949)) ([#2955](https://github.com/opensearch-project/security/pull/2955))
* Add .plugins-ml-connector to system index ([#2947](https://github.com/opensearch-project/security/pull/2947)) ([#2954](https://github.com/opensearch-project/security/pull/2954))
* Parallel test jobs for CI ([#2861](https://github.com/opensearch-project/security/pull/2861)) ([#2936](https://github.com/opensearch-project/security/pull/2936))
* Adds a check to skip serialization-deserialization if request is for same node ([#2765](https://github.com/opensearch-project/security/pull/2765)) ([#2973](https://github.com/opensearch-project/security/pull/2973))
* Add workflow cluster permissions to alerting roles and add .plugins-ml-config in the system index ([#2996](https://github.com/opensearch-project/security/pull/2996))

### Maintenance

* Match version of zstd-jni from core ([#2835](https://github.com/opensearch-project/security/pull/2835))
* Add Andrey Pleskach (Willyborankin) to Maintainers ([#2843](https://github.com/opensearch-project/security/pull/2843))
* Updates bwc versions to latest release ([#2849](https://github.com/opensearch-project/security/pull/2849))
* Add search model group permission to ml_read_access role ([#2855](https://github.com/opensearch-project/security/pull/2855)) ([#2858](https://github.com/opensearch-project/security/pull/2858))
* Format 2.x ([#2878](https://github.com/opensearch-project/security/pull/2878))
* Update snappy to 1.1.10.1 and guava to 32.0.1-jre ([#2886](https://github.com/opensearch-project/security/pull/2886)) ([#2889](https://github.com/opensearch-project/security/pull/2889))
* Resolve ImmutableOpenMap issue from core refactor ([#2908](https://github.com/opensearch-project/security/pull/2908))
* Misc changes ([#2902](https://github.com/opensearch-project/security/pull/2902)) ([#2904](https://github.com/opensearch-project/security/pull/2904))
* Bump BouncyCastle from jdk15on to jdk15to18 ([#2901](https://github.com/opensearch-project/security/pull/2901)) ([#2917](https://github.com/opensearch-project/security/pull/2917))
* Fix the import org.opensearch.core.common.Strings; and import org.opensearch.core.common.logging.LoggerMessageFormat; ([#2953](https://github.com/opensearch-project/security/pull/2953))
* Remove commons-collections 3.2.2 ([#2924](https://github.com/opensearch-project/security/pull/2924)) ([#2957](https://github.com/opensearch-project/security/pull/2957))
* Resolve CVE-2023-2976 by forcing use of Guava 32.0.1 ([#2937](https://github.com/opensearch-project/security/pull/2937)) ([#2974](https://github.com/opensearch-project/security/pull/2974))
* Bump jaxb to 2.3.8 ([#2977](https://github.com/opensearch-project/security/pull/2977)) ([#2979](https://github.com/opensearch-project/security/pull/2979))
* Update Gradle to 8.2.1 ([#2978](https://github.com/opensearch-project/security/pull/2978)) ([#2981](https://github.com/opensearch-project/security/pull/2981))
* Changed maven repo location for compatibility check ([#2988](https://github.com/opensearch-project/security/pull/2988))
* Bump guava to 32.1.1-jre ([#2976](https://github.com/opensearch-project/security/pull/2976)) ([#2990](https://github.com/opensearch-project/security/pull/2990))
