/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.dlsfls;

import java.io.IOException;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

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
    public static void createTestData() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.putJson(DLS_INDEX + "/_doc/1?refresh=true", "{\"dept\":\"sales\",\"amount\":100}");
            client.putJson(FLS_INDEX + "/_doc/1?refresh=true", "{\"public\":\"data\",\"secret\":\"hidden\"}");
            client.putJson(NO_RESTRICTION_INDEX + "/_doc/1?refresh=true", "{\"data\":\"value1\"}");
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
        try (TestRestClient client = cluster.getRestClient(DLS_USER)) {
            var response = client.putJson(DLS_INDEX + "/_doc/test1?refresh=true", "{\"dept\":\"sales\",\"amount\":400}");

            assertThat(response.getStatusCode(), is(201));
        }
    }

    @Test
    public void testDlsUser_CannotWrite_WhenSettingEnabled() throws IOException {
        setDlsWriteBlocked(true);
        try (TestRestClient client = cluster.getRestClient(DLS_USER)) {
            var response = client.putJson(DLS_INDEX + "/_doc/test2?refresh=true", "{\"dept\":\"sales\",\"amount\":400}");

            assertThat(response.getStatusCode(), is(500));
            assertThat(response.getBody(), containsString("is not supported when FLS or DLS or Fieldmasking is activated"));
        }
    }

    @Test
    public void testFlsUser_CanWrite_WhenSettingDisabled() throws IOException {
        setDlsWriteBlocked(false);
        try (TestRestClient client = cluster.getRestClient(FLS_USER)) {
            var response = client.putJson(FLS_INDEX + "/_doc/test3?refresh=true", "{\"public\":\"new_data\",\"secret\":\"new_secret\"}");

            assertThat(response.getStatusCode(), is(201));
        }
    }

    @Test
    public void testFlsUser_CannotWrite_WhenSettingEnabled() throws IOException {
        setDlsWriteBlocked(true);
        try (TestRestClient client = cluster.getRestClient(FLS_USER)) {
            var response = client.putJson(FLS_INDEX + "/_doc/test4?refresh=true", "{\"public\":\"new_data\",\"secret\":\"new_secret\"}");

            assertThat(response.getStatusCode(), is(500));
            assertThat(response.getBody(), containsString("is not supported when FLS or DLS or Fieldmasking is activated"));
        }
    }

    @Test
    public void testAdminUser_CanWrite_WhenSettingEnabled() throws IOException {
        setDlsWriteBlocked(true);
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            var response = client.putJson(DLS_INDEX + "/_doc/test6?refresh=true", "{\"dept\":\"admin\",\"amount\":999}");

            assertThat(response.getStatusCode(), is(201));
        }
    }

    @Test
    public void testDlsUser_CanRead_WhenSettingEnabled() throws IOException {
        setDlsWriteBlocked(true);
        try (TestRestClient client = cluster.getRestClient(DLS_USER)) {
            var response = client.get(DLS_INDEX + "/_search");

            assertThat(response.getStatusCode(), is(200));
        }
    }
}
