[![CI](https://github.com/opensearch-project/security/workflows/CI/badge.svg?branch=main)](https://github.com/opensearch-project/security/actions)[![codecov](https://codecov.io/gh/opensearch-project/security/branch/main/graph/badge.svg)](https://codecov.io/gh/opensearch-project/security)

<img src="https://opensearch.org/assets/img/opensearch-logo-themed.svg" height="64px">

# OpenSearch Security Plugin

OpenSearch Security is a plugin for OpenSearch that offers encryption, authentication and authorization. When combined with OpenSearch Security-Advanced Modules, it supports authentication via Active Directory, LDAP, Kerberos, JSON web tokens, SAML, OpenID and more. It includes fine grained role-based access control to indices, documents and fields. It also provides multi-tenancy support in OpenSearch Dashboards.

- [OpenSearch Security Plugin](#opensearch-security-plugin)
  - [Features](#features)
    - [Encryption](#encryption)
    - [Authentication](#authentication)
    - [Access control](#access-control)
    - [Audit/Compliance logging](#auditcompliance-logging)
    - [OpenSearch Dashboards multi-tenancy](#opensearch-dashboards-multi-tenancy)
  - [Installation](#installation)
  - [Test and Build](#test-and-build)
  - [Config hot reloading](#config-hot-reloading)
  - [Onboarding new APIs](#onboarding-new-apis)
  - [Contributing](#contributing)
  - [Getting Help](#getting-help)
  - [Code of Conduct](#code-of-conduct)
  - [Security](#security)
  - [License](#license)
  - [Copyright](#copyright)

## Features

### Encryption
* Full data in transit encryption
* Node-to-node encryption
* Certificate revocation lists
* Hot Certificate renewal

### Authentication
* Internal user database
* HTTP basic authentication
* PKI authentication
* Proxy authentication
* User Impersonation
* Active Directory / LDAP
* Kerberos / SPNEGO
* JSON web token (JWT)
* OpenID Connect (OIDC)
* SAML

### Access control
* Role-based cluster level access control
* Role-based index level access control
* User-, role- and permission management
* Document-level security
* Field-level security
* REST management API

### Audit/Compliance logging
* Audit logging
* Compliance logging for GDPR, HIPAA, PCI, SOX and ISO compliance

### OpenSearch Dashboards multi-tenancy
* True OpenSearch Dashboards multi-tenancy

## Installation

OpenSearch Security Plugin comes bundled by default as part of the OpenSearch distribution. Please refer to the [installation guide](https://opensearch.org/docs/latest/opensearch/install/index/) and  [technical documentation](https://opensearch.org/docs/latest/security-plugin/index/) for detailed information on installing and configuring the OpenSearch Security Plugin.

You can also see the [developer guide](https://github.com/opensearch-project/security/blob/main/DEVELOPER_GUIDE.md) which walks through the installation of the plugin for an OpenSearch server that doesn't initially have it.

## Test and Build

Run all tests:
```bash
./gradlew clean test
```

Run tests against local cluster:
```bash
./gradlew integTestRemote -Dtests.rest.cluster=localhost:9200 -Dtests.cluster=localhost:9200 -Dtests.clustername=docker-cluster -Dsecurity=true -Dhttps=true -Duser=admin -Dpassword=admin -Dcommon_utils.version="2.2.0.0"
```
Note: To run against a remote cluster replace cluster-name and `localhost:9200` with the IPAddress:Port of that cluster.

Build artifacts (zip, deb, rpm):
```bash
./gradlew clean assemble
artifact_zip=`ls $(pwd)/build/distributions/opensearch-security-*.zip | grep -v admin-standalone`
./gradlew buildDeb buildRpm -ParchivePath=$artifact_zip
```

This produces:

```
build/releases/opensearch-security-<VERSION>.zip
build/distributions/opensearch-security-<VERSION>.deb
build/distributions/opensearch-security-<VERSION>.rpm
```

## Config hot reloading

The Security Plugin configuration is stored in a dedicated index in OpenSearch itself. Changes to the configuration are pushed to this index via the command line tool. This triggers a reload of the configuration on all nodes automatically. This has several advantages over configuration via `opensearch.yml`:

* Configuration is stored in a central place
* No configuration files on the nodes necessary
* Configuration changes do not require a restart
* Configuration changes take effect immediately

## Onboarding new APIs

It is common practice to create new transport actions to perform different tasks between nodes when developing new APIs. For any new or existing plugins that want to onboard & integrate these actions with security, they should follow the steps below:
1. Name your action ([example](https://github.com/opensearch-project/anomaly-detection/blob/main/src/main/java/org/opensearch/ad/transport/SearchADTasksAction.java#L35)), and register it ([example](https://github.com/opensearch-project/anomaly-detection/blob/main/src/main/java/org/opensearch/ad/AnomalyDetectorPlugin.java#L935)) in your plugin. Best practice is to follow existing naming conventions, which follow a hierarchical pattern to keep the action names organized between different plugins.
2. Register the action in the [OpenSearch Security plugin](https://github.com/opensearch-project/security). Each new action is registered in the plugin as a new permission. Usually, plugins will define different roles for their plugin (e.g., read-only access, write access). Each role will contain a set of permissions. An example of adding a new permission to the `anomaly_read_access` role for the [Anomaly Detection plugin](https://github.com/opensearch-project/anomaly-detection) can be found in [this PR](https://github.com/opensearch-project/security/pull/997/files).
3. Register the action in the [OpenSearch Dashboards Security plugin](https://github.com/opensearch-project/security-dashboards-plugin). This plugin maintains the full list of possible permissions, so users can see all of them when creating new roles or searching permissions via Dashboards. An example of adding different permissions can be found in [this PR](https://github.com/opensearch-project/security-dashboards-plugin/pull/689/files).

## Contributing

See [developer guide](DEVELOPER_GUIDE.md) and [how to contribute to this project](CONTRIBUTING.md).

## Getting Help

If you find a bug, or have a feature request, please don't hesitate to open an issue in this repository.

For more information, see [project website](https://opensearch.org/) and [documentation](https://opensearch.org/docs/latest). If you need help and are unsure where to open an issue, try [forums](https://discuss.opendistrocommunity.dev/).

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](CODE_OF_CONDUCT.md). For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq), or contact [opensource-codeofconduct@amazon.com](mailto:opensource-codeofconduct@amazon.com) with any additional questions or comments.

## Security

If you discover a potential security issue in this project we ask that you notify OpenSearch Security directly via email to security@opensearch.org. Please do **not** create a public GitHub issue.

## License

This code is licensed under the Apache 2.0 License.

## Copyright

Copyright OpenSearch Contributors. See [NOTICE](NOTICE.txt) for details.
