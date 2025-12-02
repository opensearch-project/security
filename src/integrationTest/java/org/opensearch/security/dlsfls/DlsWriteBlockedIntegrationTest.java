/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.dlsfls;

import java.io.IOException;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.is;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.core.rest.RestStatus.INTERNAL_SERVER_ERROR;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.errorMessageContain;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.statusException;

/**
 * Integration tests for DLS_WRITE_BLOCKED setting which blocks write operations
 * when users have DLS, FLS, or Field Masking restrictions.
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DlsWriteBlockedIntegrationTest {

    private static final String DLS_INDEX = "dls_index";
    private static final String FLS_INDEX = "fls_index";
    private static final String NO_RESTRICTION_INDEX = "no_restriction_index";

    static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    static final User DLS_USER = new User("dls_user").roles(
        new Role("dls_role").clusterPermissions("*").indexPermissions("*").dls("{\"term\": {\"dept\": \"sales\"}}").on(DLS_INDEX)
    );

    static final User FLS_USER = new User("fls_user").roles(
        new Role("fls_role").clusterPermissions("*").indexPermissions("*").fls("public").on(FLS_INDEX)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, DLS_USER, FLS_USER)
        .build();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.index(new IndexRequest(DLS_INDEX).id("1").setRefreshPolicy(IMMEDIATE).source(Map.of("dept", "sales", "amount", 100)))
                .actionGet();
            client.index(
                new IndexRequest(FLS_INDEX).id("1").setRefreshPolicy(IMMEDIATE).source(Map.of("public", "data", "secret", "hidden"))
            ).actionGet();
            client.index(new IndexRequest(NO_RESTRICTION_INDEX).id("1").setRefreshPolicy(IMMEDIATE).source(Map.of("data", "value1")))
                .actionGet();
        }
    }

    private void setDlsWriteBlocked(boolean enabled) throws IOException {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.putJson(
                "_cluster/settings",
                String.format("{\"transient\":{\"%s\":%b}}", ConfigConstants.SECURITY_DLS_WRITE_BLOCKED, enabled)
            );
        }
    }

    @Test
    public void testDlsUser_CanWrite_WhenSettingDisabled() throws IOException {
        setDlsWriteBlocked(false);
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(DLS_USER)) {
            IndexRequest request = new IndexRequest(DLS_INDEX).id("test1")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(Map.of("dept", "sales", "amount", 400));

            var response = client.index(request, DEFAULT);

            assertThat(response.status().getStatus(), is(201));
        }
    }

    @Test
    public void testDlsUser_CannotWrite_WhenSettingEnabled() throws IOException {
        setDlsWriteBlocked(true);
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(DLS_USER)) {
            IndexRequest request = new IndexRequest(DLS_INDEX).id("test2")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(Map.of("dept", "sales", "amount", 400));

            assertThatThrownBy(
                () -> client.index(request, DEFAULT),
                allOf(
                    statusException(INTERNAL_SERVER_ERROR),
                    errorMessageContain("is not supported when FLS or DLS or Fieldmasking is activated")
                )
            );
        }
    }

    @Test
    public void testFlsUser_CanWrite_WhenSettingDisabled() throws IOException {
        setDlsWriteBlocked(false);
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(FLS_USER)) {
            IndexRequest request = new IndexRequest(FLS_INDEX).id("test3")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(Map.of("public", "new_data", "secret", "new_secret"));

            var response = client.index(request, DEFAULT);

            assertThat(response.status().getStatus(), is(201));
        }
    }

    @Test
    public void testFlsUser_CannotWrite_WhenSettingEnabled() throws IOException {
        setDlsWriteBlocked(true);
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(FLS_USER)) {
            IndexRequest request = new IndexRequest(FLS_INDEX).id("test4")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(Map.of("public", "new_data", "secret", "new_secret"));

            assertThatThrownBy(
                () -> client.index(request, DEFAULT),
                allOf(
                    statusException(INTERNAL_SERVER_ERROR),
                    errorMessageContain("is not supported when FLS or DLS or Fieldmasking is activated")
                )
            );
        }
    }

    @Test
    public void testAdminUser_CanWrite_WhenSettingEnabled() throws IOException {
        setDlsWriteBlocked(true);
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(ADMIN_USER)) {
            IndexRequest request = new IndexRequest(DLS_INDEX).id("test6")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(Map.of("dept", "admin", "amount", 999));

            var response = client.index(request, DEFAULT);

            assertThat(response.status().getStatus(), is(201));
        }
    }

    @Test
    public void testDlsUser_CanRead_WhenSettingEnabled() throws IOException {
        setDlsWriteBlocked(true);
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(DLS_USER)) {
            var response = client.search(new org.opensearch.action.search.SearchRequest(DLS_INDEX), DEFAULT);

            assertThat(response.status().getStatus(), is(200));
        }
    }
}
