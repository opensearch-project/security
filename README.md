[![CI](https://github.com/opensearch-project/security/workflows/CI/badge.svg?branch=main)](https://github.com/opensearch-project/security/actions)
[![codecov](https://codecov.io/gh/opensearch-project/security/branch/main/graph/badge.svg)](https://codecov.io/gh/opensearch-project/security)

<img src="https://opensearch.org/assets/brand/SVG/Logo/opensearch_logo_default.svg" height="64px"/>

- [OpenSearch Security](#opensearch-security)
- [Features provided by Security](#features-provided-by-security)
- [Documentation](#documentation)
- [Quick Start](#quick-start)
- [Test and Build](#test-and-build)
- [Config hot reloading](#config-hot-reloading)
- [Contributing](#contributing)
- [Getting Help](#getting-help)
- [Code of Conduct](#code-of-conduct)
- [Security](#security)
- [License](#license)
- [Copyright](#copyright)

## OpenSearch Security

OpenSearch Security is an OpenSearch plugin that offers encryption, authentication, and authorization. When combined with OpenSearch Security-Advanced Modules, it supports authentication via Active Directory, LDAP, Kerberos, JSON web tokens, SAML, OpenID and more. It includes fine grained role-based access control to indices, documents and fields. It also provides multi-tenancy support in OpenSearch Dashboards.

## Features provided by Security

### Encryption:

* Full data in transit encryption
* Node-to-node encryption
* Certificate revocation lists
* Hot Certificate renewal 

### Authentication: 
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

### Access control:
* Role-based cluster level access control
* Role-based index level access control
* User-, role- and permission management
* Document-level security
* Field-level security
* REST management API

### Audit/Compliance logging:
* Audit logging 
* Compliance logging for GDPR, HIPAA, PCI, SOX and ISO compliance

### OpenSearch Dashboards multi-tenancy
* True OpenSearch Dashboards multi-tenancy

## Documentation

Please refer to the [technical documentation](https://docs-beta.opensearch.org/docs/security/configuration/) for detailed information on installing and configuring opensearch-security plugin.

## Quick Start

* Install OpenSearch

* Install the opensearch-security plugin for your OpenSearch version 1.0.0-beta1, e.g.:

```
<OpenSearch directory>/bin/opensearch-plugin install \
  -b org.opensearch:opensearch-security:1.0.0.0-beta1
```

* ``cd`` into ``<OpenSearch directory>/plugins/opensearch-security/tools``

* Execute ``./install_demo_configuration.sh``, ``chmod`` the script first if necessary. This will generate all required TLS certificates and add the Security Plugin Configuration to your ``opensearch.yml`` file. 

* Start OpenSearch

* Test the installation by visiting ``https://localhost:9200``. When prompted, use admin/admin as username and password. This user has full access to the cluster.

* Display information about the currently logged in user by visiting ``https://localhost:9200/_plugins/_security/authinfo``.

## Test and Build

* Run all tests

```
mvn clean test
```

* Build artifacts (zip, deb, rpm)

```
mvn clean package -Padvanced -DskipTests
artifact_zip=`ls $(pwd)/target/releases/opensearch-security-*.zip | grep -v admin-standalone`
./gradlew build buildDeb buildRpm --no-daemon -ParchivePath=$artifact_zip -Dbuild.snapshot=false
```

## Config hot reloading

The Security Plugin Configuration is stored in a dedicated index in OpenSearch itself. Changes to the configuration are pushed to this index via the command line tool. This will trigger a reload of the configuration on all nodes automatically. This has several advantages over configuration via opensearch.yml:

* Configuration is stored in a central place
* No configuration files on the nodes necessary
* Configuration changes do not require a restart
* Configuration changes take effect immediately

## Contributing

See [developer guide](DEVELOPER_GUIDE.md) and [how to contribute to this project](CONTRIBUTING.md).

## Getting Help

If you find a bug, or have a feature request, please don't hesitate to open an issue in this repository.

For more information, see [project website](https://opensearch.org/) and [documentation](https://docs-beta.opensearch.org/). If you need help and are unsure where to open an issue, try [forums](https://discuss.opendistrocommunity.dev/).

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](CODE_OF_CONDUCT.md). For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq), or contact [opensource-codeofconduct@amazon.com](mailto:opensource-codeofconduct@amazon.com) with any additional questions or comments.

## Security

If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public GitHub issue.

## License

This code is licensed under the Apache 2.0 License. 

## Copyright

Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

