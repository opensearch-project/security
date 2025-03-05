#!/bin/bash

# Set version variables
security_plugin_version=$(./gradlew properties -q | grep -E '^version:' | awk '{print $2}')
security_plugin_version_no_snapshot=$(echo $security_plugin_version | sed 's/-SNAPSHOT//g')
security_plugin_version_only_number=$(echo $security_plugin_version_no_snapshot | cut -d- -f1)
test_qualifier=alpha2

# Debug print versions
echo "Versions:"
echo "security_plugin_version: $security_plugin_version"
echo "security_plugin_version_no_snapshot: $security_plugin_version_no_snapshot"
echo "security_plugin_version_only_number: $security_plugin_version_only_number"
echo "test_qualifier: $test_qualifier"

echo "Publish SPI"
./gradlew :opensearch-resource-sharing-spi:publishToMavenLocal && test -s ./spi/build/libs/opensearch-resource-sharing-spi-$security_plugin_version.jar
./gradlew :opensearch-resource-sharing-spi:publishToMavenLocal -Dbuild.snapshot=false && test -s ./spi/build/libs/opensearch-resource-sharing-spi-$security_plugin_version_no_snapshot.jar
./gradlew :opensearch-resource-sharing-spi:publishToMavenLocal -Dbuild.snapshot=false -Dbuild.version_qualifier=$test_qualifier && test -s ./spi/build/libs/opensearch-resource-sharing-spi-$security_plugin_version_only_number-$test_qualifier.jar
./gradlew :opensearch-resource-sharing-spi:publishToMavenLocal -Dbuild.version_qualifier=$test_qualifier && test -s ./spi/build/libs/opensearch-resource-sharing-spi-$security_plugin_version_only_number-$test_qualifier-SNAPSHOT.jar

echo "Publish Common"
./gradlew :opensearch-security-common:publishToMavenLocal && test -s ./common/build/libs/opensearch-security-common-$security_plugin_version.jar
./gradlew :opensearch-security-common:publishToMavenLocal -Dbuild.snapshot=false && test -s ./common/build/libs/opensearch-security-common-$security_plugin_version_no_snapshot.jar
./gradlew :opensearch-security-common:publishToMavenLocal -Dbuild.snapshot=false -Dbuild.version_qualifier=$test_qualifier && test -s ./common/build/libs/opensearch-security-common-$security_plugin_version_only_number-$test_qualifier.jar
./gradlew :opensearch-security-common:publishToMavenLocal -Dbuild.version_qualifier=$test_qualifier && test -s ./common/build/libs/opensearch-security-common-$security_plugin_version_only_number-$test_qualifier-SNAPSHOT.jar

echo "Publish Client"
./gradlew :opensearch-security-client:publishToMavenLocal && test -s ./client/build/libs/opensearch-security-client-$security_plugin_version.jar
./gradlew :opensearch-security-client:publishToMavenLocal -Dbuild.snapshot=false && test -s ./client/build/libs/opensearch-security-client-$security_plugin_version_no_snapshot.jar
./gradlew :opensearch-security-client:publishToMavenLocal -Dbuild.snapshot=false -Dbuild.version_qualifier=$test_qualifier && test -s ./client/build/libs/opensearch-security-client-$security_plugin_version_only_number-$test_qualifier.jar
./gradlew :opensearch-security-client:publishToMavenLocal -Dbuild.version_qualifier=$test_qualifier && test -s ./client/build/libs/opensearch-security-client-$security_plugin_version_only_number-$test_qualifier-SNAPSHOT.jar

echo "Build artifacts"
./gradlew assemble && \
test -s ./build/distributions/opensearch-security-$security_plugin_version.zip && \
test -s ./sample-resource-plugin/build/distributions/opensearch-sample-resource-plugin-$security_plugin_version.zip

./gradlew assemble -Dbuild.snapshot=false && \
test -s ./build/distributions/opensearch-security-$security_plugin_version_no_snapshot.zip && \
test -s ./sample-resource-plugin/build/distributions/opensearch-sample-resource-plugin-$security_plugin_version_no_snapshot.zip

./gradlew assemble -Dbuild.snapshot=false -Dbuild.version_qualifier=$test_qualifier && \
test -s ./build/distributions/opensearch-security-$security_plugin_version_only_number-$test_qualifier.zip && \
test -s ./sample-resource-plugin/build/distributions/opensearch-sample-resource-plugin-$security_plugin_version_only_number-$test_qualifier.zip

./gradlew assemble -Dbuild.version_qualifier=$test_qualifier && \
test -s ./build/distributions/opensearch-security-$security_plugin_version_only_number-$test_qualifier-SNAPSHOT.zip && \
test -s ./sample-resource-plugin/build/distributions/opensearch-sample-resource-plugin-$security_plugin_version_only_number-$test_qualifier-SNAPSHOT.zip

echo "Publish Plugin zip"
./gradlew publishPluginZipPublicationToZipStagingRepository && \
test -s ./build/distributions/opensearch-security-$security_plugin_version.zip && \
test -s ./build/distributions/opensearch-security-$security_plugin_version.pom
