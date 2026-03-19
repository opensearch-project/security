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

package org.opensearch.security.grpc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.grpc.GrpcPlugin;

import io.grpc.Channel;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;

import static org.opensearch.security.grpc.GrpcHelpers.GRPC_INDEX_ROLE;
import static org.opensearch.security.grpc.GrpcHelpers.GRPC_INDEX_USER;
import static org.opensearch.security.grpc.GrpcHelpers.SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.createHeaderInterceptor;
import static org.opensearch.security.grpc.GrpcHelpers.doBulk;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.opensearch.security.grpc.GrpcHelpers.secureChannel;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Integration test for Basic Authentication over gRPC.
 * Tests that users can successfully authenticate using HTTP Basic Auth (username:password)
 * when making gRPC requests to OpenSearch.
 */
public class BasicAuthGrpcTest {

    // Basic auth domain with default Authorization header
    public static final TestSecurityConfig.AuthcDomain BASIC_AUTH_DOMAIN = new TestSecurityConfig.AuthcDomain("basic", 0, true)
        .httpAuthenticator("basic")
        .backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .certificates(TEST_CERTIFICATES)
        .nodeSettings(SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS)
        .plugin(
            new PluginInfo(
                GrpcPlugin.class.getName(),
                "classpath plugin",
                "NA",
                Version.CURRENT,
                "21",
                GrpcPlugin.class.getName(),
                null,
                Collections.emptyList(),
                false
            )
        )
        .plugin(
            new PluginInfo(
                OpenSearchSecurityPlugin.class.getName(),
                "classpath plugin",
                "NA",
                Version.CURRENT,
                "21",
                OpenSearchSecurityPlugin.class.getName(),
                null,
                List.of("org.opensearch.transport.grpc.GrpcPlugin"),
                false
            )
        )
        .users(GRPC_INDEX_USER)
        .roles(GRPC_INDEX_ROLE)
        .rolesMapping(new TestSecurityConfig.RoleMapping(GRPC_INDEX_ROLE.getName()).users(GRPC_INDEX_USER.getName()))
        .authc(BASIC_AUTH_DOMAIN)
        .build();

    /**
     * Creates a Basic Auth header value: "Basic base64(username:password)"
     */
    private String createBasicAuthHeader(String username, String password) {
        String credentials = username + ":" + password;
        String base64Credentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        return "Basic " + base64Credentials;
    }

    @Test
    public void testBasicAuthenticationWrongPassword() throws Exception {
        String authHeader = createBasicAuthHeader(GRPC_INDEX_USER.getName(), "wrong-password");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));

        try {
            ClientInterceptor authInterceptor = createHeaderInterceptor(Map.of("Authorization", authHeader));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, authInterceptor);

            try {
                doBulk(channelWithAuth, "test-grpc-basic-wrong-pass", 2);
                fail("Expected authentication failure with wrong password");
            } catch (StatusRuntimeException e) {
                assertEquals("Expected UNAUTHENTICATED status", Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
                assertEquals("Expected specific error message", "Authentication finally failed", e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testBasicAuthenticationUnknownUser() throws Exception {
        String authHeader = createBasicAuthHeader("nonexistent-user", "any-password");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));

        try {
            ClientInterceptor authInterceptor = createHeaderInterceptor(Map.of("Authorization", authHeader));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, authInterceptor);

            try {
                doBulk(channelWithAuth, "test-grpc-basic-unknown-user", 2);
                fail("Expected authentication failure with unknown user");
            } catch (StatusRuntimeException e) {
                assertEquals("Expected UNAUTHENTICATED status", Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
                assertEquals("Expected specific error message", "Authentication finally failed", e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testBasicAuthenticationSuccess() throws Exception {
        String authHeader = createBasicAuthHeader(GRPC_INDEX_USER.getName(), GRPC_INDEX_USER.getPassword());
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));

        try {
            ClientInterceptor authInterceptor = createHeaderInterceptor(Map.of("Authorization", authHeader));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, authInterceptor);
            var bulkResp = doBulk(channelWithAuth, "test-grpc-basic-auth", 2);
            assertNotNull(bulkResp);
            assertFalse("Bulk request should succeed with valid Basic Auth", bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testBasicAuthenticationCaseInsensitiveHeader() throws Exception {
        String authHeader = createBasicAuthHeader(GRPC_INDEX_USER.getName(), GRPC_INDEX_USER.getPassword());
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));

        try {
            // Test lowercase "authorization"
            ClientInterceptor authInterceptor = createHeaderInterceptor(Map.of("authorization", authHeader));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, authInterceptor);
            var bulkResp = doBulk(channelWithAuth, "test-grpc-basic-lower", 2);
            assertNotNull(bulkResp);
            assertFalse("Bulk request should succeed with lowercase auth header", bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());

            // Test uppercase "AUTHORIZATION"
            authInterceptor = createHeaderInterceptor(Map.of("AUTHORIZATION", authHeader));
            channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, authInterceptor);
            bulkResp = doBulk(channelWithAuth, "test-grpc-basic-upper", 2);
            assertNotNull(bulkResp);
            assertFalse("Bulk request should succeed with uppercase auth header", bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());

            // Test mixed case "AutHoRiZaTION"
            authInterceptor = createHeaderInterceptor(Map.of("AutHoRiZaTION", authHeader));
            channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, authInterceptor);
            bulkResp = doBulk(channelWithAuth, "test-grpc-basic-mixed", 2);
            assertNotNull(bulkResp);
            assertFalse("Bulk request should succeed with mixed-case auth header", bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());
        } finally {
            channel.shutdown();
        }
    }
}
