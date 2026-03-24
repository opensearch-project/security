/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.dlsfls;

import java.io.IOException;

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
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * Integration tests verifying that plugins.security.dfm_empty_overrides_all can be toggled
 * dynamically via the cluster settings API without requiring a node restart.
 *
 * <p>The setting controls whether a role without a DLS/FLS rule overrides roles that do have
 * restrictions. When true, a role with no restriction on an index grants full access even if
 * another mapped role restricts it.
 */
public class DfmEmptyOverridesAllDynamicSettingTest {

    static final String INDEX = "dfm_test_index";

    static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    /**
     * User with two roles:
     *  - one role that applies a DLS filter (only docs where dept=sales)
     *  - one role with a wildcard index pattern and NO DLS rule (unrestricted)
     *
     * When dfm_empty_overrides_all=true the unrestricted role wins and the user sees all docs.
     * When dfm_empty_overrides_all=false the restricted role wins and the user sees only sales docs.
     */
    static final User MIXED_ROLE_USER = new User("mixed_role_user").roles(
        new Role("dls_restricted_role").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls("{\"term\":{\"dept\":\"sales\"}}")
            .on(INDEX),
        new Role("unrestricted_wildcard_role").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").on("*")
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, MIXED_ROLE_USER)
        .build();

    @BeforeClass
    public static void createTestData() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.putJson(INDEX + "/_doc/1?refresh=true", "{\"dept\":\"sales\",\"value\":1}");
            client.putJson(INDEX + "/_doc/2?refresh=true", "{\"dept\":\"engineering\",\"value\":2}");
            client.putJson(INDEX + "/_doc/3?refresh=true", "{\"dept\":\"marketing\",\"value\":3}");
        }
    }

    private void setDfmEmptyOverridesAll(boolean enabled) throws IOException {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            HttpResponse response = client.putJson(
                "_cluster/settings",
                String.format("{\"persistent\":{\"plugins.security.dfm_empty_overrides_all\":%b}}", enabled)
            );
            assertThat("Failed to update cluster setting", response.getStatusCode(), is(200));
        }
    }

    private int countHits(TestRestClient client) throws IOException {
        HttpResponse response = client.get(INDEX + "/_search?size=10");
        assertThat("Search failed", response.getStatusCode(), is(200));
        return response.getIntFromJsonBody("/hits/total/value");
    }

    @Test
    public void testSettingFalse_restrictedRoleWins_userSeesOnlySalesDocs() throws IOException {
        setDfmEmptyOverridesAll(false);
        try (TestRestClient client = cluster.getRestClient(MIXED_ROLE_USER)) {
            int hits = countHits(client);
            assertThat("With dfm_empty_overrides_all=false, DLS filter should apply and only sales doc visible", hits, is(1));
        }
    }

    @Test
    public void testSettingTrue_unrestrictedRoleWins_userSeesAllDocs() throws IOException {
        setDfmEmptyOverridesAll(true);
        try (TestRestClient client = cluster.getRestClient(MIXED_ROLE_USER)) {
            int hits = countHits(client);
            assertThat("With dfm_empty_overrides_all=true, unrestricted role should override DLS and all docs visible", hits, is(3));
        }
    }

    @Test
    public void testDynamicToggle_fromTrueToFalse_restrictionApplied() throws IOException {
        setDfmEmptyOverridesAll(true);
        try (TestRestClient client = cluster.getRestClient(MIXED_ROLE_USER)) {
            assertThat("Expected all docs visible when setting is true", countHits(client), is(3));
        }

        setDfmEmptyOverridesAll(false);
        try (TestRestClient client = cluster.getRestClient(MIXED_ROLE_USER)) {
            assertThat("Expected only sales doc visible after toggling setting to false", countHits(client), is(1));
        }
    }

    @Test
    public void testDynamicToggle_fromFalseToTrue_restrictionLifted() throws IOException {
        setDfmEmptyOverridesAll(false);
        try (TestRestClient client = cluster.getRestClient(MIXED_ROLE_USER)) {
            assertThat("Expected only sales doc visible when setting is false", countHits(client), is(1));
        }

        setDfmEmptyOverridesAll(true);
        try (TestRestClient client = cluster.getRestClient(MIXED_ROLE_USER)) {
            assertThat("Expected all docs visible after toggling setting to true", countHits(client), is(3));
        }
    }

    @Test
    public void testAdminUser_alwaysSeesAllDocs_regardlessOfSetting() throws IOException {
        setDfmEmptyOverridesAll(false);
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            assertThat("Admin should always see all docs", countHits(client), is(3));
        }

        setDfmEmptyOverridesAll(true);
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            assertThat("Admin should always see all docs", countHits(client), is(3));
        }
    }
}
