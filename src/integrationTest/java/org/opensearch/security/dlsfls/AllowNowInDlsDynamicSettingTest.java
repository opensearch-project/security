/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.dlsfls;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * Integration tests for {@code plugins.security.allow_now_in_dls} (and its deprecated alias
 * {@code plugins.security.unsupported.allow_now_in_dls}).
 *
 * <p>The setting controls whether date math ({@code now}, {@code now-30d/d}) is permitted in
 * Document-Level Security queries. These tests show that toggling it at runtime via the cluster
 * settings API changes the behavior of an already-open index without a node restart:
 * <ul>
 *   <li>default (unset / false): a {@code now}-based DLS role fails at query time with 400;</li>
 *   <li>after enabling it: the same index returns only the documents matching the rolling window;</li>
 *   <li>after disabling it again: the index returns to rejecting {@code now}.</li>
 * </ul>
 * The value is read live from the cluster settings when the DLS query is built, so no settings
 * update consumer is required for the change to take effect.
 */
public class AllowNowInDlsDynamicSettingTest {

    static final String INDEX = "allow_now_in_dls_test_index";

    static final String SETTING = "plugins.security.allow_now_in_dls";
    static final String DEPRECATED_SETTING = "plugins.security.unsupported.allow_now_in_dls";

    static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    /** A user whose only role restricts the index to documents from the last 30 days via date math. */
    static final User DATE_MATH_USER = new User("date_math_user").roles(
        new Role("date_math_role").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls("{\"range\":{\"@timestamp\":{\"gte\":\"now-30d/d\"}}}")
            .on(INDEX)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, DATE_MATH_USER)
        // allow_now_in_dls is a Sensitive setting: updating it requires the user's role to be in
        // plugins.security.restapi.roles_enabled, in addition to cluster:admin/settings/update.
        .nodeSettings(Map.of(SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName())))
        .build();

    @BeforeClass
    public static void createTestData() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            // "recent" is within the last 30 days; "old" is well outside it.
            client.putJson(INDEX + "/_doc/recent?refresh=true", "{\"@timestamp\":\"" + nowMinusDays(1) + "\"}");
            client.putJson(INDEX + "/_doc/old?refresh=true", "{\"@timestamp\":\"" + nowMinusDays(60) + "\"}");
        }
    }

    private static String nowMinusDays(int days) {
        return java.time.LocalDate.now(java.time.ZoneOffset.UTC).minusDays(days).toString();
    }

    /**
     * Reset both keys to null after each test so method execution order (which JUnit does not
     * guarantee for a {@code @ClassRule}-shared cluster with persistent settings) cannot leak state.
     */
    @After
    public void resetSetting() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.putJson("_cluster/settings", String.format("{\"persistent\":{\"%s\":null,\"%s\":null}}", SETTING, DEPRECATED_SETTING));
        }
    }

    private void setAllowNowInDls(String settingKey, boolean value) throws IOException {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            HttpResponse response = client.putJson("_cluster/settings", String.format("{\"persistent\":{\"%s\":%b}}", settingKey, value));
            assertThat("Failed to update " + settingKey, response.getStatusCode(), is(200));
        }
    }

    private HttpResponse search() throws IOException {
        try (TestRestClient client = cluster.getRestClient(DATE_MATH_USER)) {
            return client.get(INDEX + "/_search?size=10");
        }
    }

    @Test
    public void nowInDlsIsRejectedByDefault() throws IOException {
        HttpResponse response = search();
        assertThat(response.getStatusCode(), is(400));
        assertThat(response.getBody().contains("'now' is not allowed in DLS queries"), is(true));
    }

    @Test
    public void togglingSettingEnablesAndDisablesNowOnOpenIndex() throws IOException {
        // Default: now is rejected.
        assertThat(search().getStatusCode(), is(400));

        // Enable dynamically — the already-open index now resolves now-30d/d and returns only "recent".
        setAllowNowInDls(SETTING, true);
        HttpResponse enabled = search();
        assertThat(enabled.getStatusCode(), is(200));
        assertThat(enabled.getIntFromJsonBody("/hits/total/value"), is(1));

        // Disable dynamically — the same index reverts to rejecting now.
        setAllowNowInDls(SETTING, false);
        HttpResponse disabled = search();
        assertThat(disabled.getStatusCode(), is(400));
        assertThat(disabled.getBody().contains("'now' is not allowed in DLS queries"), is(true));
    }

    @Test
    public void deprecatedUnsupportedKeyStillWorksAsFallback() throws IOException {
        // Default: now is rejected.
        assertThat(search().getStatusCode(), is(400));

        // A runtime update to ONLY the deprecated key must propagate (the new setting's update consumer
        // fires on changes to its fallback key), enabling now on the already-open index.
        setAllowNowInDls(DEPRECATED_SETTING, true);
        HttpResponse enabled = search();
        assertThat(enabled.getStatusCode(), is(200));
        assertThat(enabled.getIntFromJsonBody("/hits/total/value"), is(1));

        // And disabling it again via the deprecated key must revert the behavior, confirming the
        // propagation is the consumer firing rather than a stale default.
        setAllowNowInDls(DEPRECATED_SETTING, false);
        HttpResponse disabled = search();
        assertThat(disabled.getStatusCode(), is(400));
        assertThat(disabled.getBody().contains("'now' is not allowed in DLS queries"), is(true));
    }
}
