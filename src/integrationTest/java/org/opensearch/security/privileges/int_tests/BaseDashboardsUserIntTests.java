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

import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.DefaultObjectMapper;
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
import static org.junit.Assert.assertTrue;

/** Tests the shipped base role without recreating its permissions in test configuration. */
@RunWith(Parameterized.class)
public class BaseDashboardsUserIntTests {
    private static final TestSecurityConfig.Role BASE_ROLE = TestSecurityConfig.Role.BASE_DASHBOARDS_USER;
    private static final TestSecurityConfig.User BASE_USER = new TestSecurityConfig.User("base_user").roles(BASE_ROLE);
    private static final TestSecurityConfig.User WRITER = new TestSecurityConfig.User("tenant_writer").roles(
        BASE_ROLE,
        new TestSecurityConfig.Role("tenant_writer").tenantPermissions("kibana_all_write").on("global_tenant", "human_resources")
    );
    private static final TestSecurityConfig.User READER = new TestSecurityConfig.User("tenant_reader").roles(
        BASE_ROLE,
        new TestSecurityConfig.Role("tenant_reader").tenantPermissions("kibana_all_read").on("global_tenant", "human_resources")
    );
    private static final TestSecurityConfig.User LEGACY_USER = new TestSecurityConfig.User("legacy_user").roles(
        TestSecurityConfig.Role.KIBANA_USER
    );
    private static final TestSecurityConfig.User READ_ONLY_BASE_USER = new TestSecurityConfig.User("read_only_base_user").roles(
        TestSecurityConfig.Role.BASE_DASHBOARDS_USER_READ_ONLY,
        new TestSecurityConfig.Role("read_only_tenants").tenantPermissions("kibana_all_read").on("global_tenant", "human_resources")
    );
    private static final TestIndex GLOBAL = TestIndex.name(".kibana_1").documentCount(1).seed(1).build();
    private static final TestIndex HR = TestIndex.name(".kibana_1592542611_humanresources_1").documentCount(1).seed(2).build();

    @ClassRule
    public static final ClusterConfig.ClusterInstances CLUSTERS = new ClusterConfig.ClusterInstances(
        () -> new LocalCluster.Builder().authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(BASE_USER, WRITER, READER, LEGACY_USER, READ_ONLY_BASE_USER)
            .tenants(new TestSecurityConfig.Tenant("human_resources"))
            .indices(GLOBAL, HR)
            .aliases(new TestAlias(".kibana").on(GLOBAL), new TestAlias(".kibana_1592542611_humanresources").on(HR))
    );

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> parameters() {
        return Arrays.stream(ClusterConfig.values()).map(config -> new Object[] { config }).toList();
    }

    private final LocalCluster cluster;
    private final ClusterConfig config;

    public BaseDashboardsUserIntTests(ClusterConfig config) {
        this.config = config;
        cluster = CLUSTERS.get(config);
    }

    @Test
    public void baseRoleContainsOnlyAliasPermissions() throws Exception {
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            TestRestClient.HttpResponse response = admin.get("_plugins/_security/api/roles/base_dashboards_user");
            assertThat(response, isOk());
            var role = DefaultObjectMapper.objectMapper().readTree(response.getBody()).path("base_dashboards_user");
            assertEquals(1, role.path("index_permissions").size());
            assertEquals(
                List.of(".kibana", ".opensearch_dashboards"),
                response.getTextArrayFromJsonBody("/base_dashboards_user/index_permissions/0/index_patterns")
            );
            assertEquals(0, role.path("tenant_permissions").size());
            assertTrue(role.path("reserved").asBoolean());
            assertTrue(role.path("static").asBoolean());
        }
    }

    @Test
    public void baseRoleDoesNotGrantSharedOrGlobalTenantAccess() {
        try (TestRestClient client = cluster.getRestClient(BASE_USER)) {
            assertThat(client.get(".kibana/_search"), isForbidden());
            assertThat(client.get(".kibana/_search", new BasicHeader("securitytenant", "human_resources")), isForbidden());
        }
    }

    @Test
    public void separateTenantRoleAllowsAliasReads() {
        for (TestSecurityConfig.User user : List.of(READER, WRITER, READ_ONLY_BASE_USER)) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse global = client.get(".kibana/_search");
                assertThat(global, isOk());
                assertEquals(GLOBAL.name(), global.getTextFromJsonBody("/hits/hits/0/_index"));
                TestRestClient.HttpResponse tenant = client.get(".kibana/_search", new BasicHeader("securitytenant", "human_resources"));
                assertThat(tenant, isOk());
                assertEquals(HR.name(), tenant.getTextFromJsonBody("/hits/hits/0/_index"));
            }
        }
    }

    @Test
    public void separateTenantRoleControlsWrites() {
        try (TestRestClient reader = cluster.getRestClient(READER); TestRestClient writer = cluster.getRestClient(WRITER)) {
            BasicHeader tenant = new BasicHeader("securitytenant", "human_resources");
            assertThat(reader.postJson(".kibana/_doc", "{\"title\":\"denied\"}", tenant), isForbidden());
            assertThat(writer.postJson(".kibana/_doc", "{\"title\":\"allowed\"}", tenant), isCreated());
        }
    }

    @Test
    public void readOnlyBaseRoleWorksWithReadOnlyTenantPermissions() {
        try (TestRestClient client = cluster.getRestClient(READ_ONLY_BASE_USER)) {
            assertThat(client.postJson(".kibana/_doc", "{\"title\":\"denied\"}"), isForbidden());
            assertThat(
                client.postJson(".kibana/_doc", "{\"title\":\"denied\"}", new BasicHeader("securitytenant", "human_resources")),
                isForbidden()
            );
        }
    }

    @Test
    public void otherTenantConcreteIndexSearchIsDenied() {
        for (TestSecurityConfig.User user : List.of(BASE_USER, READER, WRITER)) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                assertThat(client.get(HR.name() + "/_search"), isForbidden());
            }
        }
    }

    @Test
    public void aliasPermissionsAlsoCoverItsBackingIndex() {
        // Index permissions on an alias are not a restriction on the spelling of the request target.
        for (TestSecurityConfig.User user : List.of(BASE_USER, READER, WRITER)) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                boolean deniedByTenantCheck = user == BASE_USER && !config.legacyPrivilegeEvaluation;
                assertThat(client.get(GLOBAL.name() + "/_search"), deniedByTenantCheck ? isForbidden() : isOk());
            }
        }
    }

    @Test
    public void concreteIndexMgetDoesNotReturnDocuments() throws Exception {
        try (TestRestClient client = cluster.getRestClient(WRITER)) {
            TestRestClient.HttpResponse response = client.postJson(
                "_mget",
                "{\"docs\":[{\"_index\":\"" + HR.name() + "\",\"_id\":\"" + HR.anyDocument().id() + "\"}]}"
            );
            if (response.getStatusCode() == 200) {
                assertEquals("security_exception", response.getTextFromJsonBody("/docs/0/error/type"));
                assertTrue(DefaultObjectMapper.objectMapper().readTree(response.getBody()).at("/docs/0/_source").isMissingNode());
            } else {
                assertThat(response, isForbidden());
            }
        }
    }

    @Test
    public void concreteIndexBulkDoesNotWriteDocuments() {
        try (TestRestClient client = cluster.getRestClient(WRITER)) {
            TestRestClient.HttpResponse response = client.postJson(
                "_bulk",
                "{\"index\":{\"_index\":\"" + HR.name() + "\",\"_id\":\"denied-bulk\"}}\n{\"title\":\"denied\"}\n"
            );
            if (response.getStatusCode() == 200) {
                assertEquals(403, response.getIntFromJsonBody("/items/0/index/status"));
                assertEquals("security_exception", response.getTextFromJsonBody("/items/0/index/error/type"));
            } else {
                assertThat(response, isForbidden());
            }
        }
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            assertEquals(404, admin.get(HR.name() + "/_doc/denied-bulk").getStatusCode());
        }
    }

    @Test
    public void legacyRoleRetainsEvaluatorSpecificBehavior() {
        try (TestRestClient client = cluster.getRestClient(LEGACY_USER)) {
            // V4 protects tenant indices independently of the legacy role's wildcard grant.
            assertThat(client.get(HR.name() + "/_search"), config.legacyPrivilegeEvaluation ? isOk() : isForbidden());
        }
    }
}
