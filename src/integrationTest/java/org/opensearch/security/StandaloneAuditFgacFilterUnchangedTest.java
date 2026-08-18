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
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
 * FGAC regression guard for the settings-filter narrowing.
 *
 * The narrowing in {@code OpenSearchSecurityPlugin.getSettingsFilter()} is gated to SSL-only mode; an FGAC
 * node must keep filtering the entire {@code plugins.security.audit.*} subtree. In FGAC the real audit config
 * lives in the {@code .opendistro_security} index (managed via the security REST API), not cluster settings,
 * so nothing under that subtree should surface from a settings response.
 *
 * The audit config value is set statically (node settings) rather than via {@code PUT _cluster/settings}: the
 * dynamic audit settings are registered {@code Property.Sensitive}, and in FGAC {@code SecurityFilter} blocks a
 * runtime cluster-settings update to a sensitive key unless the caller holds a {@code restapi.roles_enabled}
 * role. That write guard is orthogonal to the read filter under test here; setting the value statically
 * exercises the read filter directly (it strips the subtree regardless of how the value was configured).
 * Statically-set values surface via {@code GET _nodes/settings}, so that is where we assert the filter applies.
 */
public class StandaloneAuditFgacFilterUnchangedTest {

    private static final String AUDIT_CONFIG_PREFIX = ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX; // plugins.security.audit.config.
    // Values that must NOT surface in FGAC because the broad audit.* filter still applies.
    private static final String FGAC_HIDDEN_TOKEN = "fgac_should_be_hidden";
    // A nested endpoint credential (not Property.Filtered): only the endpoints.* pattern hides it. Setting it in
    // FGAC guards against a future refactor accidentally applying the SSL-only narrow filter to all modes.
    private static final String FGAC_ENDPOINT_SECRET = "fgac_endpoint_should_be_hidden";

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(
        new TestSecurityConfig.Role("all_access").clusterPermissions("*").indexPermissions("*").on("*")
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .nodeSettings(
            // Statically configure a dynamic audit setting plus a nested endpoint credential; the broad FGAC
            // filter (plugins.security.audit.*, which covers both config.* and endpoints.*) must strip both.
            Map.of(
                AUDIT_CONFIG_PREFIX + "ignore_users",
                List.of(FGAC_HIDDEN_TOKEN),
                ConfigConstants.SECURITY_AUDIT_CONFIG_ENDPOINTS + ".fgacsink.config.password",
                FGAC_ENDPOINT_SECRET
            )
        )
        .users(ADMIN_USER)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .build();

    @Test
    public void fgacModeStillFiltersAuditSettings() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            // Statically-set node settings surface via _nodes/settings; the broad audit.* filter must strip them.
            HttpResponse get = client.get("_nodes/settings?flat_settings=true");
            assertThat(get.getBody(), get.getStatusCode(), equalTo(200));
            // FGAC keeps the broad filter, so the audit subtree must NOT come back — neither the config.* key
            // nor the endpoints.* group setting (proving both patterns still apply in non-SSL-only mode).
            assertThat(get.getBody(), not(containsString(AUDIT_CONFIG_PREFIX + "ignore_users")));
            assertThat(get.getBody(), not(containsString(FGAC_HIDDEN_TOKEN)));
            assertThat(get.getBody(), not(containsString(ConfigConstants.SECURITY_AUDIT_CONFIG_ENDPOINTS)));
            assertThat(get.getBody(), not(containsString(FGAC_ENDPOINT_SECRET)));
        }
    }
}
