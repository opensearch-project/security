## Version 3.9.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.9.0

### Breaking Changes

* Graduate resource sharing feature out of experimental, renaming settings to drop the `.experimental` segment ([#6348](https://github.com/opensearch-project/security/pull/6348))

### Features

* Enable standalone audit logging when security is fully disabled (`plugins.security.disabled: true`) for compliance without TLS or authentication ([#6341](https://github.com/opensearch-project/security/pull/6341))
* Add `audit_request_id` correlation field to all audit events for cross-event request tracing ([#6343](https://github.com/opensearch-project/security/pull/6343))
* Add `user_agent`, `user_roles`, and `auth_method` fields to audit events for improved investigability ([#6344](https://github.com/opensearch-project/security/pull/6344))
* Add API path filtering for request body logging in audit events to reduce log volume for high-throughput actions ([#6347](https://github.com/opensearch-project/security/pull/6347))
* Enrich Log4j MDC with audit event attributes to enable native log routing by category, user, or action ([#6349](https://github.com/opensearch-project/security/pull/6349))
* Add audit logging for resource sharing authorization events with dedicated categories for access granted, denied, and sharing changes ([#6352](https://github.com/opensearch-project/security/pull/6352))
* Add workspace-aware sharing records so resource visibility can be driven by workspace membership ([#6374](https://github.com/opensearch-project/security/pull/6374))
* Support request header attributes as substitutions in document-level security queries ([#6310](https://github.com/opensearch-project/security/pull/6310))
* Support wildcard matching in WLM principal username and role auto-tagging rules ([#6324](https://github.com/opensearch-project/security/pull/6324))
* Support multiple `ResourceProvider` registrations per shared resource index ([#6323](https://github.com/opensearch-project/security/pull/6323))

### Enhancements

* Add setting to ignore source cluster security roles on cross-cluster search requests for independent remote access control ([#6402](https://github.com/opensearch-project/security/pull/6402))
* Allow standalone granular REST API permissions without requiring `roles_enabled` membership ([#6493](https://github.com/opensearch-project/security/pull/6493))
* Add missing index actions (`point_in_time/create`, `point_in_time/delete`, `resolve/index`, `field_caps*`) to `ppl_full_access` role ([#6471](https://github.com/opensearch-project/security/pull/6471))
* Expose dynamic audit configuration via cluster settings in SSL-only mode so the dashboards plugin can read current state ([#6392](https://github.com/opensearch-project/security/pull/6392))
* Create parent-linked sharing entries for child resources written without an authenticated user context ([#6373](https://github.com/opensearch-project/security/pull/6373))
* Support neural and k-NN queries with hybrid document-level security ([#6428](https://github.com/opensearch-project/security/pull/6428))
* Keep hybrid DLS safe across mixed-version clusters by replacing the sentinel value with a dedicated header ([#6451](https://github.com/opensearch-project/security/pull/6451))
* Copy security tools scripts to `bin/` directory in assembly to preserve executable permissions after plugin installation ([#6023](https://github.com/opensearch-project/security/pull/6023))
* Reject JWT subjects that use reserved internal `plugin:` or API-token `token:` prefixes ([#6494](https://github.com/opensearch-project/security/pull/6494))
* Preserve authentication for self-referential cross-cluster search connections ([#6474](https://github.com/opensearch-project/security/pull/6474))
* Retry API token metadata loading during startup when cluster is temporarily blocked or master not yet discovered ([#6472](https://github.com/opensearch-project/security/pull/6472))
* Return HTTP 403 when API tokens feature is disabled instead of allowing unusable token creation ([#6351](https://github.com/opensearch-project/security/pull/6351))
* Use `User` directly as authenticated `Subject` and `Principal`, removing the redundant `UserSubjectImpl` wrapper ([#6419](https://github.com/opensearch-project/security/pull/6419))

### Bug Fixes

* Fix parent-child query detection across classloaders by matching on registered writeable names instead of `instanceof` ([#6346](https://github.com/opensearch-project/security/pull/6346))
* Fix Apache HttpClient 5.6 hostname verification so `NoopHostnameVerifier` works correctly for SecurityAdmin `-nhnv` and test clients ([#6407](https://github.com/opensearch-project/security/pull/6407))
* Fix Bouncy Castle 1.85.2 upgrade by keeping `bcpkix-jdk18on` and `bcutil-jdk18on` at compatible 1.85 versions ([#6488](https://github.com/opensearch-project/security/pull/6488))
* Fix ML model registration failure caused by Jackson 3 self-referential serialization of `User.getPrincipal()` ([#6460](https://github.com/opensearch-project/security/pull/6460))
* Require explicit opt-in (`enable_standalone: true`) for standalone audit logging to prevent unintended audit index writes from stale demo configuration ([#6368](https://github.com/opensearch-project/security/pull/6368))
* Deduplicate bulk audit events by only iterating sub-items at the `BulkShardRequest` level ([#6390](https://github.com/opensearch-project/security/pull/6390))
* Add missing `enable_standalone` setting to `StandaloneAuditBodyLoggingExclusionTest` to fix deterministic test failures ([#6372](https://github.com/opensearch-project/security/pull/6372))

### Infrastructure

* Only provision Eclipse JDT formatter when running a spotless task to prevent intermittent CI failures from P2 mirror timeouts ([#6438](https://github.com/opensearch-project/security/pull/6438))
* Stabilize parallel test cluster startup with worker-specific port bands and improved collision handling ([#6466](https://github.com/opensearch-project/security/pull/6466))
* Stabilize resource test Reactor Netty client to honor protocol configuration and bound resource usage ([#6467](https://github.com/opensearch-project/security/pull/6467))
* Harden migrate tests for single-provider resources with no `typeField` ([#6454](https://github.com/opensearch-project/security/pull/6454))
* Group CodeQL dependency updates together to prevent individual PR failures ([#6509](https://github.com/opensearch-project/security/pull/6509))
* Replace `RestHighLevelClient` with OpenSearch Java Client in tests ([#6420](https://github.com/opensearch-project/security/pull/6420))
* Replace `RestHighLevelClient` with `OpenSearchClient` in `HttpClient` ([#6489](https://github.com/opensearch-project/security/pull/6489))
* Replace `RestHighLevelClient` with `OpenSearchClient` in `SecurityAdmin` and remove `opensearch-rest-high-level-client` dependency ([#6492](https://github.com/opensearch-project/security/pull/6492))
* Switch from `snakeyaml` to `snakeyaml-engine` for YAML processing to align with Jackson 3.x ([#6408](https://github.com/opensearch-project/security/pull/6408))

### Documentation

* Clarify that demo installer password checks are independent of REST API password validation settings ([#6449](https://github.com/opensearch-project/security/pull/6449))

### Maintenance

* Bump com.google.guava:guava from 33.6.0-jre to 33.7.1-jre ([#6429](https://github.com/opensearch-project/security/pull/6429))
* Bump at.yawk.lz4:lz4-java from 1.11.1 to 1.11.2 ([#6386](https://github.com/opensearch-project/security/pull/6386))
* Bump ch.qos.logback:logback-classic from 1.5.38 to 1.6.0 ([#6328](https://github.com/opensearch-project/security/pull/6328))
* Bump ch.qos.logback:logback-classic from 1.6.0 to 1.6.1 ([#6366](https://github.com/opensearch-project/security/pull/6366))
* Bump ch.qos.logback:logback-classic from 1.6.1 to 1.6.3 ([#6403](https://github.com/opensearch-project/security/pull/6403))
* Bump commons-codec:commons-codec from 1.22.0 to 1.22.1 ([#6365](https://github.com/opensearch-project/security/pull/6365))
* Bump commons-validator:commons-validator from 1.10.1 to 1.11.0 ([#6387](https://github.com/opensearch-project/security/pull/6387))
* Bump com.google.googlejavaformat:google-java-format from 1.35.0 to 1.36.1 ([#6364](https://github.com/opensearch-project/security/pull/6364))
* Bump com.diffplug.spotless from 8.10.1 to 8.10.2 ([#6491](https://github.com/opensearch-project/security/pull/6491))
* Bump com.github.spotbugs from 6.5.9 to 6.5.10 ([#6379](https://github.com/opensearch-project/security/pull/6379))
* Bump com.github.spotbugs from 6.5.10 to 6.5.11 ([#6443](https://github.com/opensearch-project/security/pull/6443))
* Bump com.autonomousapps.build-health from 3.17.0 to 3.18.0 ([#6363](https://github.com/opensearch-project/security/pull/6363))
* Bump com.autonomousapps.build-health from 3.18.0 to 3.19.1 ([#6446](https://github.com/opensearch-project/security/pull/6446))
* Bump io.dropwizard.metrics:metrics-core from 4.2.39 to 4.2.40 ([#6483](https://github.com/opensearch-project/security/pull/6483))
* Bump io.github.vishwakarma:zjsonpatch from 0.6.2 to 0.6.3 ([#6334](https://github.com/opensearch-project/security/pull/6334))
* Bump io.projectreactor:reactor-core from 3.8.6 to 3.8.7 ([#6484](https://github.com/opensearch-project/security/pull/6484))
* Bump net.bytebuddy:byte-buddy from 1.18.11 to 1.18.12 ([#6425](https://github.com/opensearch-project/security/pull/6425))
* Bump net.bytebuddy:byte-buddy from 1.18.12 to 1.18.13 ([#6485](https://github.com/opensearch-project/security/pull/6485))
* Bump org.bouncycastle:bcprov-jdk18on from 1.85.2 to 1.86 ([#6510](https://github.com/opensearch-project/security/pull/6510))
* Bump org.codehaus.plexus:plexus-utils from 3.6.1 to 3.6.2 ([#6423](https://github.com/opensearch-project/security/pull/6423))
* Bump org.eclipse.platform:org.eclipse.core.runtime from 3.34.200 to 3.35.0 ([#6496](https://github.com/opensearch-project/security/pull/6496))
* Bump org.eclipse.platform:org.eclipse.equinox.common from 3.20.400 to 3.21.0 ([#6500](https://github.com/opensearch-project/security/pull/6500))
* Bump org.gradle.test-retry from 1.6.5 to 1.6.6 ([#6502](https://github.com/opensearch-project/security/pull/6502))
* Bump org.scala-lang:scala3-library_3 from 3.8.4 to 3.9.0 ([#6440](https://github.com/opensearch-project/security/pull/6440))
* Bump spring_framework from 7.0.8 to 7.0.9 ([#6427](https://github.com/opensearch-project/security/pull/6427))
* Bump gradle-wrapper from 9.6.1 to 9.7.0 ([#6389](https://github.com/opensearch-project/security/pull/6389))
* Bump gradle-wrapper from 9.7.0 to 9.7.1 ([#6447](https://github.com/opensearch-project/security/pull/6447))

### Refactoring

* Clarify cluster node request classification by renaming `isInterClusterRequest` to `isLocalClusterNodeRequest` and `isTrustedClusterRequest` to `isRemoteClusterNodeRequest` ([#6326](https://github.com/opensearch-project/security/pull/6326))
* Rename authenticated user transport variables to remove legacy `Subject`-oriented naming ([#6432](https://github.com/opensearch-project/security/pull/6432))
* Clarify transport security request flow by extracting header filtering, cross-cluster decoration, and incoming request helpers ([#6476](https://github.com/opensearch-project/security/pull/6476))
* Centralize transport identity propagation into `TransportIdentityContext` for direct, remote, and stream requests ([#6477](https://github.com/opensearch-project/security/pull/6477))
