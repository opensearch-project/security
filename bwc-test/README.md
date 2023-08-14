## Run BWC Tests

### Setup env var
```sh
export GIT_PROJECT_ROOT="/home/petern/git" # Change as needed
```

### Build OpenSearch with the patch
```sh
cd ~/git/OpenSearch/
git remote add scrawfor99 https://github.com/scrawfor99/OpenSearch.git
git fetch scrawfor99
git checkout scrawfor99/bwcFix
git merge origin/main
./gradlew build-tools:publishToMavenLocal
./gradlew distribution:archives:linux-tar:assemble
```

### Build security
```sh
cd ../security
git remote add scrawfor99 https://github.com/scrawfor99/OpenSearch.git
git checkout scrawfor99/testClusterChanges
git merge origin/main
```

### Build and update 3.0.0.0 version of security plugin bwc folder
```sh
./gradlew assemble
mkdir -p ${GIT_PROJECT_ROOT}/security/bwc-test/src/test/resources/3.0.0.0
cp ${GIT_PROJECT_ROOT}/security/build/distributions/opensearch-security-3.0.0.0-SNAPSHOT.zip ${GIT_PROJECT_ROOT}/security/bwc-test/src/test/resources/3.0.0.0/opensearch-security-3.0.0.0-SNAPSHOT.zip
```

### Get most recent 2.9.0.0 build so upgrade test can go from 2.9 -> 3.0

```sh
mkdir -p ${GIT_PROJECT_ROOT}/security/bwc-test/src/test/resources/2.9.0.0
wget https://repo1.maven.org/maven2/org/opensearch/plugin/opensearch-security/2.9.0.0/opensearch-security-2.9.0.0.zip
mv opensearch-security-2.9.0.0.zip ${GIT_PROJECT_ROOT}/security/bwc-test/src/test/resources/2.9.0.0/opensearch-security-2.9.0.0.zip
```

### Run bwc tests (from root of security repo)

```sh
./gradlew -p bwc-test clean bwcTestSuite \
   -Dtests.security.manager=false \
   -Dtests.opensearch.http.protocol=https \
   -Dtests.opensearch.username=admin \
   -Dtests.opensearch.password=admin \
   -PcustomDistributionUrl="/home/petern/git/opensearch/distribution/archives/linux-tar/build/distributions/opensearch-min-3.0.0-SNAPSHOT-linux-x64.tar.gz" \
   -i
```

#### Remarks:
 * `-Dtests.security.manager=false` - Handles access issues attempting to read the certificates from the file system
 * `-Dtests.opensearch.http.protocol=https` - Tells the wait for cluster startup task to do the right thing
 * `-PcustomDistributionUrl=...` uses a custom build of the distribution of opensearch, might be able to fallback to maven local?