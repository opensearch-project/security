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

import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;

/**
 * Integration test verifying that cluster-level actions (_mget, _msearch, _bulk) targeting the
 * dashboards index are denied when the user does not have access to the specified tenant.
 */
public class MultiTenancyIntTests {

    static final TestSecurityConfig.Tenant TENANT_A = new TestSecurityConfig.Tenant("tenant_a").description("Tenant A");

    // user_a has kibana_user role with access to tenant_a only
    static final TestSecurityConfig.User USER_A = new TestSecurityConfig.User("user_a").roles(
        TestSecurityConfig.Role.KIBANA_USER,
        new TestSecurityConfig.Role("user_a_role").clusterPermissions("cluster_composite_ops")
            .tenantPermissions("kibana_all_write")
            .on("tenant_a")
    );

    // user_b owns a separate tenant
    static final TestSecurityConfig.User USER_B = new TestSecurityConfig.User("user_b").roles(
        TestSecurityConfig.Role.KIBANA_USER,
        new TestSecurityConfig.Role("user_b_role").clusterPermissions("cluster_composite_ops")
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_A, USER_B)
        .tenants(TENANT_A)
        .build();

    /**
     * User A uses _mget targeting .kibana with a tenant they don't have access to.
     * This should be denied.
     */
    @Test
    public void mget_unauthorizedTenantAccess_shouldBeDenied() {
        try (TestRestClient restClient = cluster.getRestClient(USER_A)) {
            TestRestClient.HttpResponse response = restClient.postJson("_mget", """
                {
                  "docs": [
                    {
                      "_index": ".kibana",
                      "_id": "some_doc"
                    }
                  ]
                }
                """, new BasicHeader("securitytenant", "user_b"));

            assertThat(response, isForbidden());
        }
    }

    /**
     * User A uses _msearch targeting .kibana with a tenant they don't have access to.
     * This should be denied.
     */
    @Test
    public void msearch_unauthorizedTenantAccess_shouldBeDenied() {
        try (TestRestClient restClient = cluster.getRestClient(USER_A)) {
            TestRestClient.HttpResponse response = restClient.postJson("_msearch", """
                {"index":".kibana"}
                {"size":10, "query":{"match_all":{}}}
                """, new BasicHeader("securitytenant", "user_b"));

            assertThat(response, isForbidden());
        }
    }

    /**
     * User A uses _bulk to attempt to write to .kibana in a tenant they don't have access to.
     * This should be denied.
     */
    @Test
    public void bulk_unauthorizedTenantAccess_shouldBeDenied() {
        try (TestRestClient restClient = cluster.getRestClient(USER_A)) {
            TestRestClient.HttpResponse response = restClient.postJson("_bulk", """
                { "index" : { "_index" : ".kibana", "_id" : "test_doc_1" } }
                { "type": "dashboard", "title": "test" }
                """, new BasicHeader("securitytenant", "user_b"));

            assertThat(response, isForbidden());
        }
    }
}
