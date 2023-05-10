# Developer Guide

So you want to contribute code to OpenSearch Security? Excellent! We're glad you're here. Here's what you need to do.

- [Developer Guide](#developer-guide)
  - [Prerequisites](#prerequisites)
    - [Native platforms](#native-platforms)
  - [Building](#building)
  - [Using IntelliJ IDEA](#using-intellij-idea)
  - [Running integration tests](#running-integration-tests)
    - [Bulk test runs](#bulk-test-runs)
    - [Checkstyle Violations](#checkstyle-violations)
  - [Submitting Changes](#submitting-changes)
  - [Backports](#backports)

## Prerequisites

> Please make sure to follow the OpenSearch [Install Prerequisites](https://github.com/opensearch-project/OpenSearch/blob/main/DEVELOPER_GUIDE.md#install-prerequisites) before starting for the first time.

OpenSearch Security runs as a plugin of OpenSearch. You can [download a minimal release of OpenSearch](https://opensearch.org/downloads.html#minimal) and then install the Security plugin there. However, we will compile OpenSearch Security using source code so that we are pulling in changes from the latest commit.

### Native platforms

Not all platforms natively support OpenSearch, to view distribution availability please check these [issues](https://github.com/opensearch-project/opensearch-build/issues?q=label%3Adistributions).

On MacOS / PC the OpenSearch distribution can be run with Docker. This distribution contains the released version of OpenSearch including the security plugin. If you wish to use the Docker image for development, you will need to follow the steps found on the [Developing with Docker](DEVELOPING_WITH_DOCKER.md) guide.

To get started, follow the [getting started section](https://github.com/opensearch-project/OpenSearch/blob/main/DEVELOPER_GUIDE.md#getting-started) of OpenSearch's developer guide. This will get OpenSearch up and running built from source code. You can skip the `./gradlew check` step to save some time. You should follow the steps until you reach the point where you can run a successful `curl localhost:9200` call. Great! now kill the server with `Ctrl+C`.

Next, run the following commands to copy the built code (snapshot) to a new folder in a different location. (This where you'll be running the OpenSearch service). Run this from the base directory of the OpenSearch fork you cloned above:
```bash
export OPENSEARCH_HOME=~/<your-folder-location>/opensearch-*
export OPENSEARCH_BUILD=distribution/archives/darwin-tar/build/install/opensearch-*
cp -Rf $OPENSEARCH_BUILD $OPENSEARCH_HOME
```

Choose `$OPENSEARCH_HOME` as the base folder where your server will live, and adjust `$OPENSEARCH_BUILD` based on your version and OS (this is an example running on MacOS, hence `darwin`.)

Let's test and see if we can run the server!

```bash
cd $OPENSEARCH_HOME
./bin/opensearch
```

The `curl localhost:9200` call should succeed again. Kill the server with `Ctrl+c`. We are now ready to install the security plugin.


>Worth noting:\
> The version of OpenSearch and the security plugin must match as there is an explicit version check at startup. This can be a bit confusing as, for example, at the time of writing this guide, the `main` branch of this security plugin builds version `3.0.0.0-SNAPSHOT` compatible with OpenSearch `3.0.0`. Check the expected compatible version in `build.gradle` file [here](https://github.com/opensearch-project/security/blob/main/build.gradle) and make sure you get the correct branch from OpenSearch when building that project.
> 
> The line to look for: `opensearch_version = System.getProperty("opensearch.version", "x")`
> 
> Alternatively, you can find the compatible version of OpenSearch by running in project root folder
> ```
> ./gradlew properties -q | grep -E '^version:' | awk '{print $2}'
> ```

## Building

First create a fork of this repo and clone it locally. You should then change to the directory containing the clone and run this to build the project:

```bash
./gradlew clean assemble
```

To install the built plugin into the OpenSearch server run:

```bash
export OPENSEARCH_SECURITY_HOME=$OPENSEARCH_HOME/plugins/opensearch-security
mkdir $OPENSEARCH_SECURITY_HOME
cp build/distributions/opensearch-security-*.zip $OPENSEARCH_SECURITY_HOME
cd $OPENSEARCH_SECURITY_HOME
unzip opensearch-security-*.zip
rm opensearch-security-*.zip
mkdir $OPENSEARCH_HOME/config/opensearch-security
mv config/* $OPENSEARCH_HOME/config/opensearch-security/
rm -rf config/
```

To install the demo certificates and default configuration, answer `y` to the first two questions and `n` to the last one. The log should look like below:

```bash
./tools/install_demo_configuration.sh
OpenSearch Security Demo Installer
 ** Warning: Do not use on production or public reachable systems **
Install demo certificates? [y/N] y
Initialize Security Modules? [y/N] y
Cluster mode requires maybe additional setup of:
  - Virtual memory (vm.max_map_count)

Enable cluster mode? [y/N] n
Basedir: /Users/XXXXX/Test/opensearch-*
OpenSearch install type: .tar.gz on
OpenSearch config dir: /Users/XXXXX/Test/opensearch-*/config
OpenSearch config file: /Users/XXXXX/Test/opensearch-*/config/opensearch.yml
OpenSearch bin dir: /Users/XXXXX/Test/opensearch-*/bin
OpenSearch plugins dir: /Users/XXXXX/Test/opensearch-*/plugins
OpenSearch lib dir: /Users/XXXXX/Test/opensearch-*/lib
Detected OpenSearch Version: x-content-*
Detected OpenSearch Security Version: *

### Success
### Execute this script now on all your nodes and then start all nodes
### OpenSearch Security will be automatically initialized.
### If you like to change the runtime configuration
### change the files in ../config and execute:
"/Users/XXXXX/Test/opensearch-*/plugins/opensearch-security/tools/securityadmin.sh" -cd "/Users/XXXXX/Test/opensearch-*/config/opensearch-security/" -icl -key "/Users/XXXXX/Test/opensearch-*/config/kirk-key.pem" -cert "/Users/XXXXX/Test/opensearch-*/config/kirk.pem" -cacert "/Users/XXXXX/Test/opensearch-*/config/root-ca.pem" -nhnv
### or run ./securityadmin_demo.sh
### To use the Security Plugin ConfigurationGUI
### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/admin.
### (Ignore the SSL certificate warning because we installed self-signed demo certificates)
```

Now if we start our server again and try the original `curl localhost:9200`, it will fail.
Try this command instead: `curl -XGET https://localhost:9200 -u 'admin:admin' --insecure`. It should succeed.

You can also make this call to return the authenticated user details:

```bash
curl -XGET https://localhost:9200/_plugins/_security/authinfo -u 'admin:admin' --insecure

{
  "user": "User [name=admin, backend_roles=[admin], requestedTenant=null]",
  "user_name": "admin",
  "user_requested_tenant": null,
  "remote_address": "[::1]:57755",
  "backend_roles": [
    "admin"
  ],
  "custom_attribute_names": [],
  "roles": [
    "own_index",
    "all_access"
  ],
  "tenants": {
    "global_tenant": true,
    "admin_tenant": true,
    "admin": true
  },
  "principal": null,
  "peer_certificates": "0",
  "sso_logout_url": null
}
```

## Using IntelliJ IDEA

Launch IntelliJ IDEA, choose **Project from Existing Sources**, and select directory with Gradle build script (`build.gradle`).

## Running integration tests

Locally these can be run with `./gradlew test` with detailed results being available at `${project-root}/build/reports/tests/test/index.html`. You can also run tests through an IDEs JUnit test runner.

Integration tests are automatically run on all pull requests for all supported versions of the JDK. These must pass for change(s) to be merged. Detailed logs of these test results are available by going to the GitHub Actions workflow summary view and downloading the workflow run of the tests. If you see multiple tests listed with different JDK versions, you can download the version with whichever JDK you are interested in. After extracting the test file on your local machine, integration tests results can be found at `./tests/tests/index.html`.

### Bulk test runs

To collect reliability data on test runs, there is a manual GitHub action workflow called `Bulk Integration Test`.  The workflow is started for a branch on this project or in a fork by going to [GitHub action workflows](https://github.com/opensearch-project/security/actions/workflows/integration-tests.yml) and selecting `Run Workflow`.

### Checkstyle Violations

Checkstyle enforces several rules within this codebase. Sometimes it will be necessary for exceptions to be made when dealing with components that are set for deprecation. This can happen when the new version of a deprecation-path component is unavailable. There are two formats of suppression that can be used when dealing with violations of this nature, one for disabling a single rule, or another for disabling all rules. It is best to only disable specific rules when possible.

*Execute Checkstyle*
```
./gradlew checkstyleMain checkstyleTest 
```

*Example violation*
```
[ant:checkstyle] [ERROR] /local/home/security/src/main/java/org/opensearch/security/configuration/DlsFlsValveImpl.java:178: Usage should be switched to cluster manager [RegexpSingleline]
```

*Single Rule Suppression*
```
    // CS-SUPPRESS-SINGLE: RegexpSingleline See http://github/issues/1234
    ...
    Code that violates the rule
    ...
    // CS-ENFORCE-SINGLE
```

*Suppression All Checkstyle Rules*
```
  // CS-SUPRESS-ALL: Legacy code to be deleted in Z.Y.X see http://github/issues/1234
  ...
  // CS-ENFORCE-ALL
```

## Submitting Changes

See [CONTRIBUTING](CONTRIBUTING.md).

## Backports

The Github workflow in [`backport.yml`](.github/workflows/backport.yml) creates backport PRs automatically when the
original PR with an appropriate label `backport <backport-branch-name>` is merged to main with the backport workflow
run successfully on the PR. For example, if a PR on main needs to be backported to `1.x` branch, add a label
`backport 1.x` to the PR and make sure the backport workflow runs on the PR along with other checks. Once this PR is
merged to main, the workflow will create a backport PR to the `1.x` branch.
