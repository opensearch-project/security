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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.opensearch.security.support.ConfigConstants.*;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ServiceAccountAuthenticationTest {

    public static final String DEFAULT_PASSWORD = "secret";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    public static final String SERVICE_ACCOUNT_USER_NAME = "admin-extension";

    private static final TestSecurityConfig.Role SERVICE_ACCOUNT_ADMIN_ROLE = new TestSecurityConfig.Role("admin-extension-role")
        .clusterPermissions("*")
        .indexPermissions("*", "system:admin/system_index")
        .on("*");

    static final TestSecurityConfig.User SERVICE_ACCOUNT_ADMIN_USER = new TestSecurityConfig.User(SERVICE_ACCOUNT_USER_NAME).roles(
        SERVICE_ACCOUNT_ADMIN_ROLE
    ).attr("service", true);

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .users(ADMIN_USER, SERVICE_ACCOUNT_ADMIN_USER)
        .nodeSettings(
            Map.of(
                SECURITY_SYSTEM_INDICES_PERMISSIONS_ENABLED_KEY,
                true,
                SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX,
                true,
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_admin__all_access")
            )
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .build();

    // TODO: REMOVE THIS DEBUGGING TEST CASE
    @Test
    public void testClusterHealthWithAdminCred() {
        try (TestRestClient client = cluster.getRestClient("admin", DEFAULT_PASSWORD)) {
            client.confirmCorrectCredentials("admin");
            TestRestClient.HttpResponse response = client.get("_cluster/health");
            response.assertStatusCode(HttpStatus.SC_OK);
            System.out.println(response);
        }
    }

    @Test
    public void testClusterHealthWithServiceAccountCred() throws JsonProcessingException {
        try (TestRestClient client = cluster.getRestClient("admin-extension", DEFAULT_PASSWORD)) {
            client.confirmCorrectCredentials("admin-extension");
            TestRestClient.HttpResponse response = client.get("_cluster/health");
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);

            String responseBody = response.getBody();
            assertNotNull("Response body should not be null", responseBody);

            ObjectMapper objectMapper = new ObjectMapper();
            String typeField = objectMapper.readTree(responseBody).at("/error/root_cause/0/type").asText();

            assertEquals("security_exception", typeField);
        }
    }
}
