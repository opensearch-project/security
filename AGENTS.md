# AGENTS.md — OpenSearch Security Plugin

Guidance for AI coding agents working in this repository.

## Keeping This File Up to Date

This file should be updated automatically as part of any change that affects the information documented here. Do not treat it as a separate maintenance task — include the `AGENTS.md` update in the same commit or PR as the relevant code change. Examples of changes that should trigger an update:

- Adding, removing, or renaming source packages or top-level directories
- Changing the build system, required JDK version, or key Gradle tasks
- Adding or retiring test suites or testing conventions
- Changing code style tooling or static analysis configuration
- Updating contribution workflows (branching strategy, backport process, commit conventions, etc.)
- Adding new security-specific patterns or constraints agents should be aware of

When in doubt, update the file.

## Repository Overview

OpenSearch Security is a plugin that adds authentication, authorization, TLS encryption, audit logging, and multi-tenancy to OpenSearch. The plugin intercepts all requests at the REST and transport layers before they reach OpenSearch action handlers.

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed flow diagrams.

## Repository Structure

```
src/
  main/java/org/opensearch/security/
    action/         # Custom OpenSearch actions registered by the plugin
    auditlog/       # Audit and compliance logging framework
    auth/           # Authentication backends (basic, PKI, proxy, LDAP, Kerberos, JWT, OIDC, SAML)
    authtoken/      # On-behalf-of (OBO) token issuance for extensions
    compliance/     # Field-level security and compliance (GDPR/HIPAA/PCI/SOX) features
    configuration/  # Security index management, config hot-reload
    dlic/           # Dynamic configuration REST API (roles, users, role-mappings, etc.)
    filter/         # REST and transport request/response filter pipeline
    hasher/         # Password hashing utilities
    http/           # HTTP/HTTPS layer integration
    httpclient/     # Internal HTTP client for auth backend calls
    identity/       # Subject and identity abstractions
    opensaml/       # OpenSAML integration utilities
    privileges/     # Authorization engine (role evaluation, DLS/FLS)
    queries/        # DLS query building
    resources/      # Resource sharing and access control
    rest/           # REST action handlers and route registration
    securityconf/   # Security configuration model (roles, mappings, users)
    setting/        # Plugin settings definitions
    ssl/            # TLS configuration for transport and HTTP layers
    state/          # Cluster security state management
    support/        # Shared support utilities
    tools/          # Admin tools (securityadmin)
    transport/      # Transport layer interception and enforcement
    user/           # User model and attribute handling
    util/           # General utilities
  test/             # Unit tests
  integrationTest/  # Integration tests (require a running OpenSearch cluster)
spi/                # Security Plugin Interface — public extension points for other plugins
libs/
  opensaml/         # Vendored/shaded OpenSAML library
sample-resource-plugin/  # Example plugin using the resource-sharing SPI
config/             # Default demo configuration (certs, roles, users, mappings)
tools/              # Shell scripts: securityadmin.sh, install_demo_configuration.sh
scripts/            # CI/CD helper scripts
bwc-test/           # Backwards-compatibility tests
checkstyle/         # Checkstyle rule configuration
formatter/          # Eclipse JDT formatter configuration
```

## Build

**Minimum JDK: 21.** `JAVA_HOME` must be set.

The plugin version must match the target OpenSearch version. Check `build.gradle`:

```groovy
opensearch_version = System.getProperty("opensearch.version", "3.8.0-SNAPSHOT")
```

```bash
./gradlew clean assemble          # build the plugin zip
./gradlew check                   # all verification tasks (unit tests, integration, static analysis)
./gradlew precommit               # precommit checks only (run before every commit)
./gradlew spotlessApply           # auto-fix Java formatting
```

## Testing

### Unit Tests

- Located in `src/test/`
- Run with: `./gradlew test`
- HTML results: `build/reports/tests/test/index.html`
- Run a specific test:
  ```bash
  ./gradlew test --tests "org.opensearch.security.auth.BackendRegistryTests"
  ```
- Repeat a test for reliability using the `@Repeat` annotation:
  ```java
  @Rule public RepeatRule repeatRule = new RepeatRule();

  @Test
  @Repeat(10)
  public void testMethod() { ... }
  ```

### Integration Tests

- Located in `src/integrationTest/`
- Subdomain suites: `api`, `auditlog`, `dlsfls`, `grpc`, `hash`, `http`, `privileges`, `rest`, `ssl`, `support`, `systemindex`, `user`, `util`
- Run all integration tests: `./gradlew integrationTest`
- Run a specific suite (as defined in `build.gradle`):
  ```bash
  ./gradlew ciSecurityIntegrationTest   # all *Integ* tests
  ./gradlew dlicDlsflsTest              # Document- and Field-Level Security
  ./gradlew dlicRestApiTest             # REST Management API
  ./gradlew sslTest                     # SSL/TLS tests
  ./gradlew crossClusterTest            # Cross-cluster tests
  ```
- Run a specific integration test class:
  ```bash
  ./gradlew integrationTest --tests "org.opensearch.security.ssl.OpenSSLTest"
  ```

### Writing Good Tests

- Prefer unit tests over integration tests when equivalent coverage is achievable.
- Never use `Thread.sleep` — use `assertBusy` or `CountDownLatch` for async conditions.
- Clean up all resources in `@After` / `@AfterClass` methods.
- Integration tests must not depend on test-execution order.
- Use `./gradlew test -Dtests.iters=N` to repeat with varied random seeds when validating stability.

## Code Style and Static Analysis

### Formatting (Spotless + Eclipse JDT)

```bash
./gradlew spotlessJavaCheck   # verify formatting
./gradlew spotlessApply       # auto-fix formatting
```

Configuration: `formatter/` directory.

### Checkstyle

```bash
./gradlew checkstyleMain checkstyleTest
```

To suppress a violation for a legitimate reason (e.g. deprecated-path code awaiting removal):

```java
// CS-SUPPRESS-SINGLE: RegexpSingleline See https://github.com/opensearch-project/security/issues/XXXX
// ... violating code ...
// CS-ENFORCE-SINGLE
```

To suppress all rules on a legacy block:

```java
// CS-SUPPRESS-ALL: Legacy code to be deleted in X.Y.Z see https://github.com/opensearch-project/security/issues/XXXX
// ... legacy code ...
// CS-ENFORCE-ALL
```

### SpotBugs

SpotBugs runs on main sources (not tests). Include-filter: `spotbugs-include.xml`.

```bash
./gradlew spotbugsMain
```

## Security-Specific Guidelines

- **Never log sensitive data** — passwords, tokens, certificates, and PII must never appear in log output.
- **TLS changes** must be tested against both the transport layer and the HTTP layer.
- **Privilege evaluation** (`privileges/`) is on the hot path — keep it free of I/O, side-effects, and unnecessary allocations.
- **Security index schema changes** require migration logic for existing clusters; do not change field names or types without a migration path.
- **New REST endpoints** under `/_plugins/_security/` must be registered in the appropriate handler class and protected with an authorization check.
- **SPI changes** (`spi/`) are public API consumed by external plugins. Apply `@PublicApi`, `@InternalApi`, or `@ExperimentalApi` annotations and maintain backwards compatibility accordingly.
- **Resource sharing** changes should be validated against the sample plugin in `sample-resource-plugin/`.
- **FIPS compliance** — the build supports FIPS-140-3 mode (`gradle.properties`). Avoid cryptographic primitives that are not FIPS-approved.

## Commits

Write commit titles focused on **user impact**, not implementation details:

- ✅ `Enforce minimum TLS 1.2 on HTTP transport by default`
- ❌ `Add tlsMinVersion field to SSLConfig`

Commit title ≤ 50 characters. Leave a blank line before the body; wrap body at 72 characters. All commits must be signed off (DCO).

## Pull Requests

- Always push to your personal fork. Never push directly to `opensearch-project/security` or to `main`.
- Tests run automatically on all PRs across all supported JDK versions. All checks must pass before merging.

## Backports

The automated backport workflow has been retired. Backports must be performed manually using your preferred Git workflow — the example below uses `git cherry-pick`, but other approaches (e.g. patch files or GUI tools) are equally valid.

The most common backport targets are the branches for the current Long-Term Support (LTS) releases.

**Example using `git cherry-pick`:**

```bash
# Check out a new branch from the 2.19 LTS branch
git fetch upstream
git checkout -b backport/my-fix-2.19 upstream/2.19

# Cherry-pick the commit(s) from main (use -x to record the source SHA)
git cherry-pick -x <commit-sha>

# Push to your fork and open a PR against the target branch
git push origin backport/my-fix-2.19
```

Resolve any conflicts, then open a PR against the target branch referencing the original PR for reviewer context.

For further guidance see [CONTRIBUTING.md](CONTRIBUTING.md) and [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md).
