[![CI](https://github.com/opensearch-project/security/workflows/CI/badge.svg?branch=main)](https://github.com/opensearch-project/security/actions)[![codecov](https://codecov.io/gh/opensearch-project/security/branch/main/graph/badge.svg)](https://codecov.io/gh/opensearch-project/security)

<img src="https://opensearch.org/assets/img/opensearch-logo-themed.svg" height="64px">

# OpenSearch Security Plugin

OpenSearch Security is a plugin for OpenSearch that offers encryption, authentication and authorization. When combined with OpenSearch Security-Advanced Modules, it supports authentication via Active Directory, LDAP, Kerberos, JSON web tokens, SAML, OpenID and more. It includes fine grained role-based access control to indices, documents and fields. It also provides multi-tenancy support in OpenSearch Dashboards.

- [Features](#features)
- [Installation](#installation)
- [Test and Build](#test-and-build)
- [Config hot reloading](#config-hot-reloading)
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

## Contributing

See [developer guide](DEVELOPER_GUIDE.md) and [how to contribute to this project](CONTRIBUTING.md).

## Getting Help

If you find a bug, or have a feature request, please don't hesitate to open an issue in this repository.

For more information, see [project website](https://opensearch.org/) and [documentation](https://opensearch.org/docs/latest). If you need help and are unsure where to open an issue, try [forums](https://discuss.opendistrocommunity.dev/).

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](CODE_OF_CONDUCT.md). For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq), or contact [opensource-codeofconduct@amazon.com](mailto:opensource-codeofconduct@amazon.com) with any additional questions or comments.

## Security

If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public GitHub issue.

## License

This code is licensed under the Apache 2.0 License. 

## Copyright

Copyright OpenSearch Contributors. See [NOTICE](NOTICE.txt) for details.
