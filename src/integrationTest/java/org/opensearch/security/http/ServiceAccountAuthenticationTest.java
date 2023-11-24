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

package org.opensearch.security.http;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_KEY;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_PERMISSIONS_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ServiceAccountAuthenticationTest {

    public static final String SERVICE_ATTRIBUTE = "service";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    public static final String SERVICE_ACCOUNT_USER_NAME = "test-service-account";

    static final TestSecurityConfig.User SERVICE_ACCOUNT_ADMIN_USER = new TestSecurityConfig.User(SERVICE_ACCOUNT_USER_NAME).attr(
        SERVICE_ATTRIBUTE,
        "true"
    )
        .roles(
            new TestSecurityConfig.Role("test-service-account-role").clusterPermissions("*")
                .indexPermissions("*", "system:admin/system_index")
                .on("*")
        );

    private static final TestIndex TEST_NON_SYS_INDEX = TestIndex.name("test-non-sys-index")
        .setting("index.number_of_shards", 1)
        .setting("index.number_of_replicas", 0)
        .build();

    private static final TestIndex TEST_SYS_INDEX = TestIndex.name("test-sys-index")
        .setting("index.number_of_shards", 1)
        .setting("index.number_of_replicas", 0)
        .build();

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .users(ADMIN_USER, SERVICE_ACCOUNT_ADMIN_USER)
        .nodeSettings(
            Map.of(
                SECURITY_SYSTEM_INDICES_PERMISSIONS_ENABLED_KEY,
                true,
                SECURITY_SYSTEM_INDICES_ENABLED_KEY,
                true,
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_admin__all_access"),
                SECURITY_SYSTEM_INDICES_KEY,
                List.of(TEST_SYS_INDEX.getName())
            )
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .indices(TEST_NON_SYS_INDEX, TEST_SYS_INDEX)
        .build();

    @Test
    public void testClusterHealthWithServiceAccountCred() {
        try (TestRestClient client = cluster.getRestClient(SERVICE_ACCOUNT_ADMIN_USER)) {
            client.confirmCorrectCredentials(SERVICE_ACCOUNT_USER_NAME);
            TestRestClient.HttpResponse response = client.get("_cluster/health");
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);

            String responseBody = response.getBody();

            assertNotNull("Response body should not be null", responseBody);
            assertTrue(responseBody.contains("\"type\":\"security_exception\""));
        }
    }

    @Test
    public void testReadSysIndexWithServiceAccountCred() {
        try (TestRestClient client = cluster.getRestClient(SERVICE_ACCOUNT_ADMIN_USER)) {
            client.confirmCorrectCredentials(SERVICE_ACCOUNT_USER_NAME);
            TestRestClient.HttpResponse response = client.get(TEST_SYS_INDEX.getName());
            response.assertStatusCode(HttpStatus.SC_OK);

            String responseBody = response.getBody();

            assertNotNull("Response body should not be null", responseBody);
            assertTrue(responseBody.contains(TEST_SYS_INDEX.getName()));
        }
    }

    @Test
    public void testReadNonSysIndexWithServiceAccountCred() {
        try (TestRestClient client = cluster.getRestClient(SERVICE_ACCOUNT_ADMIN_USER)) {
            client.confirmCorrectCredentials(SERVICE_ACCOUNT_USER_NAME);
            TestRestClient.HttpResponse response = client.get(TEST_NON_SYS_INDEX.getName());
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);

            String responseBody = response.getBody();

            assertNotNull("Response body should not be null", responseBody);
            assertTrue(responseBody.contains("\"type\":\"security_exception\""));
        }
    }

    @Test
    public void testReadBothWithServiceAccountCred() {
        TestRestClient client = cluster.getRestClient(SERVICE_ACCOUNT_ADMIN_USER);
        client.confirmCorrectCredentials(SERVICE_ACCOUNT_USER_NAME);
        TestRestClient.HttpResponse response = client.get((TEST_SYS_INDEX.getName() + "," + TEST_NON_SYS_INDEX.getName()));
        response.assertStatusCode(HttpStatus.SC_FORBIDDEN);

        String responseBody = response.getBody();

        assertNotNull("Response body should not be null", responseBody);
        assertTrue(responseBody.contains("\"type\":\"security_exception\""));

    }
}
