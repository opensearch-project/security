/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges.int_tests;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestAlias;
import org.opensearch.test.framework.data.TestIndex;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class BaseDashboardsUserWithoutMultitenancyIntTests {
    private static final TestSecurityConfig.User READER = new TestSecurityConfig.User("reader").roles(
        TestSecurityConfig.Role.BASE_DASHBOARDS_USER_READ_ONLY
    );
    private static final TestSecurityConfig.User WRITER = new TestSecurityConfig.User("writer").roles(
        TestSecurityConfig.Role.BASE_DASHBOARDS_USER
    );
    private static final TestIndex KIBANA = TestIndex.name(".kibana_1").documentCount(1).seed(1).build();
    private static final TestIndex DASHBOARDS = TestIndex.name(".opensearch_dashboards_1").documentCount(1).seed(2).build();

    @ClassRule
    public static final ClusterConfig.ClusterInstances CLUSTERS = new ClusterConfig.ClusterInstances(
        () -> new LocalCluster.Builder().config(new TestSecurityConfig().multitenancyEnabled(false))
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(READER, WRITER)
            .indices(KIBANA, DASHBOARDS)
            .aliases(new TestAlias(".kibana").on(KIBANA), new TestAlias(".opensearch_dashboards").on(DASHBOARDS))
    );

    @Parameterized.Parameters(name = "{0}, {1}")
    public static Collection<Object[]> parameters() {
        return Arrays.stream(ClusterConfig.values())
            .flatMap(config -> List.of(".kibana", ".opensearch_dashboards").stream().map(alias -> new Object[] { config, alias }))
            .toList();
    }

    private final LocalCluster cluster;
    private final String alias;

    public BaseDashboardsUserWithoutMultitenancyIntTests(ClusterConfig config, String alias) {
        cluster = CLUSTERS.get(config);
        this.alias = alias;
    }

    @Test
    public void bothRolesCanReadWithoutTenantPermissions() {
        for (TestSecurityConfig.User user : List.of(READER, WRITER)) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                assertThat(client.get(alias + "/_search"), isOk());
                assertThat(client.postJson(alias + "/_mget", "{\"ids\":[\"missing\"]}"), isOk());
            }
        }
    }

    @Test
    public void readOnlyRoleCannotWriteThroughAliasOrBackingIndex() {
        try (TestRestClient client = cluster.getRestClient(READER)) {
            for (String target : List.of(alias, alias + "_1")) {
                assertThat(client.putJson(target + "/_doc/denied", "{\"title\":\"denied\"}"), isForbidden());
                assertThat(client.postJson(target + "/_update/denied", "{\"doc\":{\"title\":\"denied\"}}"), isForbidden());
                assertThat(client.delete(target + "/_doc/denied"), isForbidden());
                assertThat(client.putJson(target + "/_settings", "{\"index\":{\"refresh_interval\":\"5s\"}}"), isForbidden());
            }
        }
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            assertEquals(404, admin.get(alias + "/_doc/denied").getStatusCode());
        }
    }

    @Test
    public void readOnlyRoleCannotBulkWrite() {
        try (TestRestClient client = cluster.getRestClient(READER)) {
            assertThat(
                client.postJson("_bulk", "{\"index\":{\"_index\":\"" + alias + "\",\"_id\":\"denied-bulk\"}}\n{\"title\":\"denied\"}\n"),
                isForbidden()
            );
        }
    }

    @Test
    public void writeRoleCanCreateUpdateAndDelete() {
        try (TestRestClient client = cluster.getRestClient(WRITER)) {
            assertThat(client.putJson(alias + "/_doc/write-test", "{\"title\":\"created\"}"), isCreated());
            try {
                assertThat(client.postJson(alias + "/_update/write-test", "{\"doc\":{\"title\":\"updated\"}}"), isOk());
                assertEquals("updated", client.get(alias + "/_doc/write-test").getTextFromJsonBody("/_source/title"));
            } finally {
                assertThat(client.delete(alias + "/_doc/write-test"), isOk());
            }
        }
    }

    @Test
    public void readOnlyRoleContainsNoWriteOrTenantGrants() {
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            TestRestClient.HttpResponse response = admin.get("_plugins/_security/api/roles/base_dashboards_user_read_only");
            assertThat(response, isOk());
            assertEquals(
                List.of("cluster_composite_ops_ro"),
                response.getTextArrayFromJsonBody("/base_dashboards_user_read_only/cluster_permissions")
            );
            assertEquals(
                List.of("read"),
                response.getTextArrayFromJsonBody("/base_dashboards_user_read_only/index_permissions/0/allowed_actions")
            );
            assertEquals(
                List.of(".kibana", ".opensearch_dashboards"),
                response.getTextArrayFromJsonBody("/base_dashboards_user_read_only/index_permissions/0/index_patterns")
            );
            assertEquals(List.of(), response.getTextArrayFromJsonBody("/base_dashboards_user_read_only/tenant_permissions"));
        }
    }
}
