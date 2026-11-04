/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security;

import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecuritySettings;
import org.opensearch.test.framework.audit.TestRuleAuditLogSink;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

/**
 * Verifies the settings filter behaviour for standalone audit in SSL-only mode.
 *
 * In SSL-only mode there is no {@code .opendistro_security} index, so the audit configuration lives in
 * cluster settings and the dashboards audit panel reads it back via {@code GET _cluster/settings}. The
 * security plugin's {@code getSettingsFilter()} previously stripped the entire {@code plugins.security.audit.*}
 * subtree from settings responses, which also hid the (non-secret) dynamic config the panel needs. The filter
 * was narrowed in SSL-only mode to strip only the credential-bearing group settings
 * ({@code plugins.security.audit.endpoints.*} / {@code .routes.*}).
 *
 * These tests lock in that behaviour: the dynamic config is now readable, while the credential-bearing sink
 * settings stay hidden. Secrets on the default endpoint (username/password/webhook.url) are additionally
 * registered with {@code Property.Filtered}, so OpenSearch core strips them regardless of this filter.
 */
public class StandaloneAuditSettingsFilterTest {

    // A value that must never appear in a settings response.
    private static final String SECRET_PASSWORD = "TOPSECRET_SINK_PASSWORD";
    private static final String SECRET_USERNAME = "secret_sink_user";
    private static final String SECRET_WEBHOOK_URL = "https://secret.example.test/audit-hook";
    // Nested credentials on secondary endpoints/routes. Unlike the default-endpoint secrets above, these keys
    // are NOT Property.Filtered, so only the plugins.security.audit.endpoints.* / .routes.* filters hide them.
    private static final String SECRET_ENDPOINT_VALUE = "SECRET_ENDPOINT_CREDENTIAL";
    private static final String SECRET_ROUTE_VALUE = "SECRET_ROUTE_CREDENTIAL";
    // Static external-sink infrastructure config that lives directly under config.* (not endpoints/routes) and is
    // NOT panel-managed. Registered Property.Filtered so core strips it regardless of the narrowed audit filter.
    private static final String SECRET_SIEM_HOST = "secret-siem.internal.test:9200";
    private static final String SECRET_CIPHER = "SECRET_CIPHER_TLS_MARKER";
    private static final String SECRET_PROTOCOL = "SECRET_PROTOCOL_TLS_MARKER";

    private static final String AUDIT_CONFIG_PREFIX = ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX; // plugins.security.audit.config.
    private static final String COMPLIANCE_PREFIX = SecuritySettings.COMPLIANCE_PREFIX; // plugins.security.audit.compliance.

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.ofEntries(
                Map.entry(ConfigConstants.SECURITY_SSL_ONLY, true),
                Map.entry(ConfigConstants.SECURITY_AUDIT_ENABLE_STANDALONE, true),
                Map.entry("plugins.security.audit.type", TestRuleAuditLogSink.class.getName()),
                // Non-secret dynamic config set statically: must SURFACE after the filter is narrowed.
                Map.entry(AUDIT_CONFIG_PREFIX + "disabled_rest_categories", List.of("GRANTED_PRIVILEGES")),
                // Credential-bearing default-endpoint settings (Property.Filtered): must stay HIDDEN.
                Map.entry(AUDIT_CONFIG_PREFIX + ConfigConstants.SECURITY_AUDIT_CONFIG_USERNAME, SECRET_USERNAME),
                Map.entry(AUDIT_CONFIG_PREFIX + ConfigConstants.SECURITY_AUDIT_CONFIG_PASSWORD, SECRET_PASSWORD),
                Map.entry(AUDIT_CONFIG_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_URL, SECRET_WEBHOOK_URL),
                // A secondary endpoint with a nested credential and no "type" (SinkProvider logs and skips it,
                // so the node still boots). Only the endpoints.* filter keeps this credential out of responses.
                Map.entry(ConfigConstants.SECURITY_AUDIT_CONFIG_ENDPOINTS + ".secretsink.config.password", SECRET_ENDPOINT_VALUE),
                // A route under a non-category key (AuditMessageRouter logs and skips unknown categories, so the
                // node still boots). Only the routes.* filter keeps this credential out of responses.
                Map.entry(ConfigConstants.SECURITY_AUDIT_CONFIG_ROUTES + ".secretroute.config.token", SECRET_ROUTE_VALUE),
                // Static external-sink infrastructure config under config.* (host list + TLS ciphers/protocols).
                // These are NOT covered by the endpoints.*/routes.* filters; they must stay hidden via Property.Filtered.
                Map.entry(
                    AUDIT_CONFIG_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS,
                    List.of(SECRET_SIEM_HOST)
                ),
                Map.entry(
                    AUDIT_CONFIG_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS,
                    List.of(SECRET_CIPHER)
                ),
                Map.entry(
                    AUDIT_CONFIG_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS,
                    List.of(SECRET_PROTOCOL)
                )
            )
        )
        .sslOnly(true)
        .build();

    /**
     * The bug fix: dynamic audit config written through cluster settings is readable back via
     * GET _cluster/settings (previously the whole subtree was stripped by the broad
     * plugins.security.audit.* filter).
     *
     * The filter operates at the prefix level, so covering both dynamic subtrees
     * (audit.config.* and audit.compliance.*) across both value shapes (list + bool) is sufficient
     * to prove all ~17 dynamic settings flow through — exhaustively PUT-ing every key would only
     * re-test the same prefix match.
     */
    @Test
    public void dynamicAuditConfigIsReadableViaClusterSettings() {
        // A representative slice of the ~17 dynamic settings: both prefixes, list + bool.
        String body = "{\"persistent\":{"
            + "\""
            + AUDIT_CONFIG_PREFIX
            + "ignore_users\":[\"ignore_users_token\"],"
            + "\""
            + AUDIT_CONFIG_PREFIX
            + "disabled_rest_categories\":[\"GRANTED_PRIVILEGES\"],"
            + "\""
            + AUDIT_CONFIG_PREFIX
            + "log_request_body\":false,"
            + "\""
            + COMPLIANCE_PREFIX
            + "enabled\":false,"
            + "\""
            + COMPLIANCE_PREFIX
            + "read_watched_fields\":[\"read_watched_token\"],"
            + "\""
            + COMPLIANCE_PREFIX
            + "write_watched_indices\":[\"write_watched_token\"]"
            + "}}";

        try (TestRestClient client = cluster.getRestClient()) {
            HttpResponse put = client.putJson("_cluster/settings", body);
            assertThat(put.getBody(), put.getStatusCode(), equalTo(200));

            HttpResponse get = client.get("_cluster/settings?flat_settings=true");
            assertThat(get.getBody(), get.getStatusCode(), equalTo(200));
            String read = get.getBody();

            // Both subtrees and both value shapes must come back through the narrowed filter.
            assertThat(read, containsString(AUDIT_CONFIG_PREFIX + "ignore_users"));
            assertThat(read, containsString("ignore_users_token"));
            assertThat(read, containsString(AUDIT_CONFIG_PREFIX + "disabled_rest_categories"));
            assertThat(read, containsString(AUDIT_CONFIG_PREFIX + "log_request_body"));
            assertThat(read, containsString(COMPLIANCE_PREFIX + "enabled"));
            assertThat(read, containsString(COMPLIANCE_PREFIX + "read_watched_fields"));
            assertThat(read, containsString("read_watched_token"));
            assertThat(read, containsString(COMPLIANCE_PREFIX + "write_watched_indices"));
            assertThat(read, containsString("write_watched_token"));
        }
    }

    /**
     * Narrowing the filter must not expose credentials. Statically-configured settings surface via
     * GET _nodes/settings; the non-secret config is now visible, but the Filtered sink secrets and the
     * endpoints/routes group settings must not appear.
     */
    @Test
    public void auditSecretsAreNotExposedInNodeSettings() {
        try (TestRestClient client = cluster.getRestClient()) {
            HttpResponse get = client.get("_nodes/settings?flat_settings=true");
            assertThat(get.getBody(), get.getStatusCode(), equalTo(200));
            String body = get.getBody();

            // Non-secret audit config surfaces now that the wildcard is narrowed in SSL-only mode.
            assertThat(body, containsString(AUDIT_CONFIG_PREFIX + "disabled_rest_categories"));

            // Credential-bearing values must never appear.
            assertThat(body, not(containsString(SECRET_PASSWORD)));
            assertThat(body, not(containsString(SECRET_USERNAME)));
            assertThat(body, not(containsString(SECRET_WEBHOOK_URL)));

            // The credential-bearing group settings stay filtered out, including the nested endpoint/route
            // credentials (which are not Property.Filtered, so only our endpoints.*/routes.* filters protect them).
            assertThat(body, not(containsString(SECRET_ENDPOINT_VALUE)));
            assertThat(body, not(containsString(SECRET_ROUTE_VALUE)));
            assertThat(body, not(containsString(ConfigConstants.SECURITY_AUDIT_CONFIG_ENDPOINTS)));
            assertThat(body, not(containsString(ConfigConstants.SECURITY_AUDIT_CONFIG_ROUTES)));

            // Static external-sink infrastructure under config.* (host list, TLS ciphers/protocols) is not covered
            // by the endpoints.*/routes.* filters; Property.Filtered must keep it out of settings responses so
            // narrowing the audit wildcard does not disclose backend audit topology to unauthenticated clients.
            assertThat(body, not(containsString(SECRET_SIEM_HOST)));
            assertThat(body, not(containsString(SECRET_CIPHER)));
            assertThat(body, not(containsString(SECRET_PROTOCOL)));
        }
    }
}
