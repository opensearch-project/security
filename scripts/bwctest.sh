#!/bin/bash

set -e

export JAVA_HOME=$(/usr/libexec/java_home -v 21)

PREVIOUS_BRANCH=2.x

cd ..

echo "Building bwc tests for OpenSearch Security..."
./gradlew -p bwc-test build -x test -x integTest

echo "Building current version..."
./gradlew clean assemble

CURRENT_VERSION=$(./gradlew properties -Dbuild.snapshot=false | grep ^version: | awk '{split($0, a, ": ");print a[2]}')

echo "Build current version: $CURRENT_VERSION"

echo "Cloning OpenSearch Security repository from tag $PREVIOUS_BRANCH..."

TMPDIR=$(mktemp -d)
cd "$TMPDIR"
git clone -b $PREVIOUS_BRANCH https://github.com/opensearch-project/security.git --depth 1 .

echo "Building old version..."

export JAVA_HOME=$(/usr/libexec/java_home -v 17)

./gradlew clean assemble

OLD_VERSION=$(./gradlew properties -Dbuild.snapshot=false | grep ^version: | awk '{split($0, a, ": ");print a[2]}')

echo "Build old version: $OLD_VERSION"

cd -

echo "Copying resources from current version $CURRENT_VERSION..."
mkdir -p ./bwc-test/src/test/resources/"$CURRENT_VERSION"
cp ./build/distributions/opensearch-security-"$CURRENT_VERSION"-SNAPSHOT.zip ./bwc-test/src/test/resources/"$CURRENT_VERSION"

echo "Copying resources from old version $OLD_VERSION..."
mkdir -p ./bwc-test/src/test/resources/"$OLD_VERSION"
cp "$TMPDIR"/build/distributions/opensearch-security-"$OLD_VERSION"-SNAPSHOT.zip ./bwc-test/src/test/resources/"$OLD_VERSION"

echo "Cleaning up temporary files..."
rm -rf "$TMPDIR"

export JAVA_HOME=$(/usr/libexec/java_home -v 21)

echo "Starting tests..."
./gradlew -p bwc-test bwcTestSuite -Dtests.security.manager=false -Dtests.opensearch.secure=true -Dtests.opensearch.username=admin -Dtests.opensearch.password=admin -Dbwc.version.previous="$OLD_VERSION" -Dbwc.version.next="$CURRENT_VERSION" -i
