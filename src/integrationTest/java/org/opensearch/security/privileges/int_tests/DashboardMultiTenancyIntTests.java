/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.privileges.int_tests;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestAlias;
import org.opensearch.test.framework.data.TestIndex;
import org.opensearch.test.framework.matcher.RestIndexMatchers;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.cluster.TestRestClient.json;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnResponseIndexMatcher.containsExactly;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.limitedTo;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * An integration test matrix for Dashboards multi-tenancy. Verifies both read and write operations
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DashboardMultiTenancyIntTests {

    // -------------------------------------------------------------------------------------------------------
    // Tenants
    // -------------------------------------------------------------------------------------------------------

    static final TestSecurityConfig.Tenant TENANT_HUMAN_RESOURCES = new TestSecurityConfig.Tenant("human_resources").description(
        "Human Resources Department Tenant"
    );

    static final TestSecurityConfig.Tenant TENANT_BUSINESS_INTELLIGENCE = new TestSecurityConfig.Tenant("business_intelligence")
        .description("Business Intelligence Department Tenant");

    // -------------------------------------------------------------------------------------------------------
    // Test indices and aliases
    // Each alias has exactly one index associated with it; while the alias is called .kibana_something,
    // the index is called .kibana_something_1 to simulate versioning of the .kibana index.
    // -------------------------------------------------------------------------------------------------------

    // Global tenant (default .kibana index)
    static final TestIndex dashboards_index_global = TestIndex.name(".kibana_1").documentCount(10).seed(1).build();

    static final TestAlias dashboards_alias_global = new TestAlias(".kibana").on(dashboards_index_global);

    static final TestIndex dashboards_index_human_resources = TestIndex.name(".kibana_1592542611_humanresources_1")
        .documentCount(10)
        .seed(2)
        .build();

    static final TestAlias dashboards_alias_human_resources = new TestAlias(".kibana_1592542611_humanresources").on(
        dashboards_index_human_resources
    );

    static final TestIndex dashboards_index_business_intelligence = TestIndex.name(".kibana_1592542612_businessintelligence_1")
        .documentCount(10)
        .seed(3)
        .build();

    static final TestAlias dashboards_alias_business_intelligence = new TestAlias(".kibana_1592542612_businessintelligence").on(
        dashboards_index_business_intelligence
    );

    // Private tenant for hr_employee user
    static final TestIndex dashboards_index_private_hr = TestIndex.name(".kibana_-1843063229_hremployee_1")
        .documentCount(10)
        .seed(4)
        .build();

    static final TestAlias dashboards_alias_private_hr = new TestAlias(".kibana_-1843063229_hremployee").on(dashboards_index_private_hr);

    // Private tenant for bi_analyst user
    static final TestIndex dashboards_index_private_bi = TestIndex.name(".kibana_-1388717942_bianalyst_1")
        .documentCount(10)
        .seed(5)
        .build();

    static final TestAlias dashboards_alias_private_bi = new TestAlias(".kibana_-1388717942_bianalyst").on(dashboards_index_private_bi);

    // Private tenant for global_tenant_rw user
    static final TestIndex dashboards_index_private_global_tenant_rw = TestIndex.name(".kibana_-2043392244_globaltenantrwuser_1")
        .documentCount(10)
        .seed(6)
        .build();

    static final TestAlias dashboards_alias_private_global_tenant_rw = new TestAlias(".kibana_-2043392244_globaltenantrwuser").on(
        dashboards_index_private_global_tenant_rw
    );

    // Private tenant for global_tenant_rw user
    static final TestIndex dashboards_index_private_global_tenant_ro = TestIndex.name(".kibana_2022541844_globaltenantrouser_1")
        .documentCount(10)
        .seed(7)
        .build();

    static final TestAlias dashboards_alias_private_global_tenant_ro = new TestAlias(".kibana_2022541844_globaltenantrouser").on(
        dashboards_index_private_global_tenant_ro
    );

    // Private tenant for no_tenant user
    static final TestIndex dashboards_index_private_no_tenant = TestIndex.name(".kibana_-1011980094_notenantuser_1")
        .documentCount(10)
        .seed(8)
        .build();

    static final TestAlias dashboards_alias_private_no_tenant = new TestAlias(".kibana_-1011980094_notenantuser").on(
        dashboards_index_private_no_tenant
    );

    // Private tenant for wildcard_tenant user
    static final TestIndex dashboards_index_private_wc_tenant = TestIndex.name(".kibana_-904711333_wildcardtenantuser_1")
        .documentCount(10)
        .seed(9)
        .build();

    static final TestAlias dashboards_alias_private_wc_tenant = new TestAlias(".kibana_-904711333_wildcardtenantuser").on(
        dashboards_index_private_wc_tenant
    );

    static final TestSecurityConfig.User.MetadataKey<RestIndexMatchers.IndexMatcher> READ = new TestSecurityConfig.User.MetadataKey<>(
        "read",
        RestIndexMatchers.IndexMatcher.class
    );

    static final TestSecurityConfig.User.MetadataKey<RestIndexMatchers.IndexMatcher> WRITE = new TestSecurityConfig.User.MetadataKey<>(
        "write",
        RestIndexMatchers.IndexMatcher.class
    );

    // -------------------------------------------------------------------------------------------------------
    // Test users
    // -------------------------------------------------------------------------------------------------------

    /**
     * HR Employee with read-write access to human_resources tenant and read-only to business_intelligence tenant.
     * Also has access to their private tenant.
     */
    static final TestSecurityConfig.User HR_EMPLOYEE = new TestSecurityConfig.User("hr_employee").description(
        "r/w to HR tenant, r to BI tenant"
    )
        .roles(
            new TestSecurityConfig.Role("hr_employee_role").clusterPermissions("cluster_composite_ops")
                .tenantPermissions("kibana_all_write")
                .on("human_resources")
                .tenantPermissions("kibana_all_read")
                .on("business_intelligence")
        )
        .reference(
            READ,
            limitedTo(
                dashboards_alias_private_hr,
                dashboards_index_private_hr,
                dashboards_alias_business_intelligence,
                dashboards_index_business_intelligence,
                dashboards_alias_human_resources,
                dashboards_index_human_resources
            )
        )
        .reference(
            WRITE,
            limitedTo(
                dashboards_alias_private_hr,
                dashboards_index_private_hr,
                dashboards_alias_human_resources,
                dashboards_index_human_resources
            )
        );

    /**
     * BI Analyst with read-write access to business_intelligence tenant only.
     */
    static final TestSecurityConfig.User BI_ANALYST = new TestSecurityConfig.User("bi_analyst").description("r/w to BI tenant")
        .roles(
            new TestSecurityConfig.Role("bi_analyst_role").clusterPermissions("cluster_composite_ops")
                .tenantPermissions("kibana_all_write")
                .on("business_intelligence")
        )
        .reference(
            READ,
            limitedTo(
                dashboards_alias_private_bi,
                dashboards_index_private_bi,
                dashboards_alias_business_intelligence,
                dashboards_index_business_intelligence
            )
        )
        .reference(
            WRITE,
            limitedTo(
                dashboards_alias_private_bi,
                dashboards_index_private_bi,
                dashboards_alias_business_intelligence,
                dashboards_index_business_intelligence
            )
        );

    static final TestSecurityConfig.User GLOBAL_TENANT_READ_WRITE_USER = new TestSecurityConfig.User("global_tenant_rw_user").description(
        "r/w to global tenant"
    )
        .roles(
            TestSecurityConfig.Role.KIBANA_USER,
            new TestSecurityConfig.Role("global_tenant_role").clusterPermissions("cluster_composite_ops")
                .tenantPermissions("kibana_all_write")
                .on("global_tenant")
        )
        .reference(
            READ,
            limitedTo(
                dashboards_alias_private_global_tenant_rw,
                dashboards_index_private_global_tenant_rw,
                dashboards_alias_global,
                dashboards_index_global
            )
        )
        .reference(
            WRITE,
            limitedTo(
                dashboards_alias_private_global_tenant_rw,
                dashboards_index_private_global_tenant_rw,
                dashboards_alias_global,
                dashboards_index_global
            )
        );

    static final TestSecurityConfig.User GLOBAL_TENANT_READ_ONLY_USER = new TestSecurityConfig.User("global_tenant_ro_user").description(
        "r/o to global tenant"
    )
        .roles(
            TestSecurityConfig.Role.KIBANA_USER,
            new TestSecurityConfig.Role("global_tenant_role").clusterPermissions("cluster_composite_ops")
                .tenantPermissions("kibana_all_read")
                .on("global_tenant")
        )
        .reference(
            READ,
            limitedTo(
                dashboards_alias_private_global_tenant_ro,
                dashboards_index_private_global_tenant_ro,
                dashboards_alias_global,
                dashboards_index_global
            )
        )
        .reference(WRITE, limitedTo(dashboards_alias_private_global_tenant_ro, dashboards_index_private_global_tenant_ro));

    /**
     * User with no tenant access (except the private tenant which every user has by default).
     */
    static final TestSecurityConfig.User NO_TENANT_USER = new TestSecurityConfig.User("no_tenant_user").description(
        "r/w only to private tenant"
    )
        .roles(new TestSecurityConfig.Role("no_tenant_role").clusterPermissions("cluster_composite_ops"))
        .reference(READ, limitedTo(dashboards_alias_private_no_tenant, dashboards_index_private_no_tenant))
        .reference(WRITE, limitedTo(dashboards_alias_private_no_tenant, dashboards_index_private_no_tenant));

    /**
     * User with wildcard tenant pattern access - can access any tenant matching the pattern.
     * This tests tenant pattern substitution feature.
     */
    static final TestSecurityConfig.User WILDCARD_TENANT_USER = new TestSecurityConfig.User("wildcard_tenant_user").description("r/w to *")
        .roles(
            TestSecurityConfig.Role.KIBANA_USER,
            new TestSecurityConfig.Role("wildcard_tenant_role").clusterPermissions("cluster_composite_ops")
                .tenantPermissions("kibana_all_write")
                .on("*")
        )
        .reference(
            READ,
            limitedTo(
                dashboards_alias_private_wc_tenant,
                dashboards_index_private_wc_tenant,
                dashboards_alias_global,
                dashboards_index_global,
                dashboards_alias_business_intelligence,
                dashboards_index_business_intelligence,
                dashboards_alias_human_resources,
                dashboards_index_human_resources
            )
        )
        .reference(
            WRITE,
            limitedTo(
                dashboards_alias_private_wc_tenant,
                dashboards_index_private_wc_tenant,
                dashboards_alias_global,
                dashboards_index_global,
                dashboards_alias_business_intelligence,
                dashboards_index_business_intelligence,
                dashboards_alias_human_resources,
                dashboards_index_human_resources
            )
        );

    static final List<TestSecurityConfig.User> USERS = List.of(
        HR_EMPLOYEE,
        BI_ANALYST,
        GLOBAL_TENANT_READ_WRITE_USER,
        GLOBAL_TENANT_READ_ONLY_USER,
        NO_TENANT_USER,
        WILDCARD_TENANT_USER
    );

    static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USERS)
            .tenants(TENANT_HUMAN_RESOURCES, TENANT_BUSINESS_INTELLIGENCE)
            .indices(
                dashboards_index_global,
                dashboards_index_human_resources,
                dashboards_index_business_intelligence,
                dashboards_index_private_hr,
                dashboards_index_private_bi,
                dashboards_index_private_global_tenant_rw,
                dashboards_index_private_global_tenant_ro,
                dashboards_index_private_no_tenant,
                dashboards_index_private_wc_tenant
            )
            .aliases(
                dashboards_alias_global,
                dashboards_alias_human_resources,
                dashboards_alias_business_intelligence,
                dashboards_alias_private_hr,
                dashboards_alias_private_bi,
                dashboards_alias_private_global_tenant_rw,
                dashboards_alias_private_global_tenant_ro,
                dashboards_alias_private_no_tenant,
                dashboards_alias_private_wc_tenant
            );
    }

    @AfterClass
    public static void stopClusters() {
        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            clusterConfig.shutdown();
        }
    }

    final TestSecurityConfig.User user;
    final LocalCluster cluster;
    final ClusterConfig clusterConfig;

    @Test
    public void search_withTenantHeader_humanResources() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = restClient.get(
                ".kibana/_search/?pretty",
                new BasicHeader("securitytenant", "human_resources")
            );

            assertThat(
                response,
                containsExactly(dashboards_index_human_resources).at("hits.hits[*]._index").butForbiddenIfIncomplete(user.reference(READ))
            );
        }
    }

    /**
     * This should access the user's private tenant.
     */
    @Test
    public void search_withTenantHeader_private() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = restClient.get(".kibana/_search/?pretty", new BasicHeader("securitytenant", "__user__"));

            assertThat(
                response,
                containsExactly(
                    dashboards_index_private_hr,
                    dashboards_index_private_bi,
                    dashboards_index_private_global_tenant_rw,
                    dashboards_index_private_global_tenant_ro,
                    dashboards_index_private_no_tenant,
                    dashboards_index_private_wc_tenant
                ).at("hits.hits[*]._index").reducedBy(user.reference(READ))
            );
        }
    }

    /**
     * If the tenant header is absent, the global tenant should be used.
     */
    @Test
    public void search_withoutTenantHeader() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {

            TestRestClient.HttpResponse response = restClient.get(".kibana/_search/?pretty");

            assertThat(
                response,
                containsExactly(dashboards_index_global).at("hits.hits[*]._index").butForbiddenIfIncomplete(user.reference(READ))
            );
        }
    }

    @Test
    public void search_nonExistingTenant() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse res = restClient.get(
                ".kibana/_search/?pretty",
                new BasicHeader("securitytenant", "nonexistent_tenant")
            );

            assertThat(res, isForbidden());
        }
    }

    @Test
    public void msearch_withTenantHeader_humanResources() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = restClient.postJson("_msearch/?pretty", """
                {"index":".kibana", "ignore_unavailable": false}
                {"size":10, "query":{"bool":{"must":{"match_all":{}}}}}
                """, new BasicHeader("securitytenant", "human_resources"));

            assertThat(
                response,
                containsExactly(dashboards_index_human_resources).at("responses[*].hits.hits[*]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isOk())
            );
        }
    }

    @Test
    public void get_withTenantHeader_humanResources() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String docId = dashboards_index_human_resources.anyDocument().id();

            TestRestClient.HttpResponse response = restClient.get(
                ".kibana/_doc/" + docId + "?pretty",
                new BasicHeader("securitytenant", "human_resources")
            );

            assertThat(
                response,
                containsExactly(dashboards_index_human_resources).at("_index").reducedBy(user.reference(READ)).whenEmpty(isForbidden())
            );
        }
    }

    @Test
    public void mget_withTenantHeader_humanResources() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String docId = dashboards_index_human_resources.anyDocument().id();

            TestRestClient.HttpResponse response = restClient.postJson("_mget/?pretty", """
                {
                  "docs": [
                    {
                      "_index": ".kibana",
                      "_id": "%s"
                    }
                  ]
                }
                """.formatted(docId), new BasicHeader("securitytenant", "human_resources"));

            assertThat(
                response,
                containsExactly(dashboards_index_human_resources).at("docs[?(@.found == true)]._index")
                    .reducedBy(user.reference(READ))
                    .whenEmpty(isOk())
            );
        }
    }

    @Test
    public void index_withTenantHeader_humanResources() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String indexDoc = """
                {
                  "foo": "bar"
                }
                """;

            TestRestClient.HttpResponse response = restClient.putJson(
                ".kibana/_doc/test_mt_write_1?pretty",
                indexDoc,
                new BasicHeader("securitytenant", "human_resources")
            );

            if (user.reference(WRITE).covers(dashboards_index_human_resources)) {
                assertThat(response, isCreated());
            } else {
                assertThat(response, isForbidden());
            }
        } finally {
            delete(dashboards_index_human_resources.name() + "/_doc/test_mt_write_1");
        }
    }

    @Test
    public void bulk_withTenantHeader_humanResources() {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            String bulkBody = """
                { "index" : { "_index" : ".kibana", "_id" : "mt_bulk_doc_1" } }
                { "type": "config", "config": { "buildNum": 12345 } }
                { "index" : { "_index" : ".kibana", "_id" : "mt_bulk_doc_2" } }
                { "type": "index-pattern", "index-pattern": { "title": "logs*" } }
                """;

            TestRestClient.HttpResponse response = restClient.postJson(
                "_bulk?pretty",
                bulkBody,
                new BasicHeader("securitytenant", "human_resources")
            );

            assertThat(
                response,
                containsExactly(dashboards_index_human_resources).at("items[*].index[?(@.result == 'created')]._index")
                    .reducedBy(user.reference(WRITE))
                    .whenEmpty(isOk())
            );
        } finally {
            delete(
                dashboards_index_human_resources.name() + "/_doc/mt_bulk_doc_1",
                dashboards_index_human_resources.name() + "/_doc/mt_bulk_doc_2"
            );
        }
    }

    @Test
    public void delete_withTenantHeader_humanResources() {
        String testDocId = "test_delete_doc_" + UUID.randomUUID();

        try (TestRestClient restClient = cluster.getRestClient(user); TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {

            TestRestClient.HttpResponse response = adminRestClient.put(
                dashboards_index_human_resources.name() + "/_doc/" + testDocId + "?pretty",
                json("foo", "bar"),
                new BasicHeader("securitytenant", "human_resources")
            );

            assertThat(response, isCreated());

            TestRestClient.HttpResponse deleteRes = restClient.delete(
                ".kibana/_doc/" + testDocId + "?pretty",
                new BasicHeader("securitytenant", "human_resources")
            );

            if (user.reference(WRITE).covers(dashboards_index_human_resources)) {
                assertThat(deleteRes, isOk());
                assertThat(deleteRes.getBody(), containsString("\"result\" : \"deleted\""));
            } else {
                assertThat(deleteRes, isForbidden());
            }
        } finally {
            delete(dashboards_index_human_resources.name() + "/_doc/" + testDocId);
        }
    }

    @ParametersFactory(shuffle = false, argumentFormatting = "%1$s, %3$s")
    public static Collection<Object[]> params() {
        List<Object[]> result = new ArrayList<>();
        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            for (TestSecurityConfig.User user : USERS) {
                result.add(new Object[] { clusterConfig, user, user.getDescription() });
            }
        }
        return result;
    }

    public DashboardMultiTenancyIntTests(
        ClusterConfig clusterConfig,
        TestSecurityConfig.User user,
        @SuppressWarnings("unused") String description
    ) {
        this.user = user;
        this.cluster = clusterConfig.cluster(DashboardMultiTenancyIntTests::clusterBuilder);
        this.clusterConfig = clusterConfig;
    }

    private void delete(String... paths) {
        try (TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {
            for (String path : paths) {
                TestRestClient.HttpResponse response = adminRestClient.delete(path);
                if (response.getStatusCode() != 200 && response.getStatusCode() != 404) {
                    throw new RuntimeException("Error while deleting " + path + "\n" + response.getBody());
                }
            }
        }
    }
}
