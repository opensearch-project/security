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

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.protobufs.BulkResponse;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.JwtConfigBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.grpc.GrpcPlugin;

import io.grpc.Channel;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.opensearch.security.grpc.GrpcHelpers.GRPC_INDEX_ROLE;
import static org.opensearch.security.grpc.GrpcHelpers.GRPC_INDEX_ROLE_NO_MAPPING;
import static org.opensearch.security.grpc.GrpcHelpers.GRPC_INDEX_USER;
import static org.opensearch.security.grpc.GrpcHelpers.GRPC_INDEX_USER_NO_MAPPING;
import static org.opensearch.security.grpc.GrpcHelpers.GRPC_SEARCH_ROLE;
import static org.opensearch.security.grpc.GrpcHelpers.GRPC_SEARCH_USER;
import static org.opensearch.security.grpc.GrpcHelpers.SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.createHeaderInterceptor;
import static org.opensearch.security.grpc.GrpcHelpers.doBulk;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.opensearch.security.grpc.GrpcHelpers.secureChannel;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class JWTGrpcInterceptorTest {
    // Graceful authentication failure message
    private static final String AUTH_FINALLY_FAILED = "Authentication finally failed";

    // User with no permissions for impersonation testing
    static final TestSecurityConfig.User GRPC_IMPERSONATING_USER = new TestSecurityConfig.User("grpc_impersonating_user");

    // JWT claims/keys
    public static final List<String> CLAIM_USERNAME = List.of("preferred-username");
    public static final List<String> CLAIM_ROLES = List.of("backend-user-roles");
    public static final String JWT_AUTH_HEADER = "jwt-auth";
    private static final KeyPair KEY_PAIR = Keys.keyPairFor(SignatureAlgorithm.RS256);
    private static final String PUBLIC_KEY = new String(Base64.getEncoder().encode(KEY_PAIR.getPublic().getEncoded()), US_ASCII);

    private String createValidJwtToken(String username, String... roles) {
        Date now = new Date();
        return Jwts.builder()
            .claim(CLAIM_USERNAME.get(0), username)
            .claim(CLAIM_ROLES.get(0), String.join(",", roles))
            .setIssuer("test-issuer")
            .setSubject(username)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + 3600 * 1000))
            .signWith(KEY_PAIR.getPrivate(), SignatureAlgorithm.RS256)
            .compact();
    }

    private String createInvalidSignatureJwtToken(String username, String... roles) {
        KeyPair wrongKeyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        Date now = new Date();
        return Jwts.builder()
            .claim(CLAIM_USERNAME.get(0), username)
            .claim(CLAIM_ROLES.get(0), String.join(",", roles))
            .setIssuer("test-issuer")
            .setSubject(username)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + 3600 * 1000))
            .signWith(wrongKeyPair.getPrivate(), SignatureAlgorithm.RS256)
            .compact();
    }

    private String createWrongClaimsJwtToken(String username, String... roles) {
        Date now = new Date();
        return Jwts.builder()
            .claim("username", username)  // Wrong claim name
            .claim("roles", String.join(",", roles))  // Wrong claim name
            .setIssuer("test-issuer")
            .setSubject(username)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + 3600 * 1000))
            .signWith(KEY_PAIR.getPrivate(), SignatureAlgorithm.RS256)
            .compact();
    }

    public static final TestSecurityConfig.AuthcDomain JWT_AUTH_DOMAIN = new TestSecurityConfig.AuthcDomain("jwt", 2).jwtHttpAuthenticator(
        new JwtConfigBuilder().jwtHeader(JWT_AUTH_HEADER).signingKey(List.of(PUBLIC_KEY)).subjectKey(CLAIM_USERNAME).rolesKey(CLAIM_ROLES)
    ).backend("noop");

    public static final TestSecurityConfig.AuthcDomain BASIC_AUTH_DOMAIN = new TestSecurityConfig.AuthcDomain("basic", 1).httpAuthenticator(
        "basic"
    ).backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .certificates(TEST_CERTIFICATES)
        .nodeSettings(SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS)
        .nodeSettings(
            Map.of(
                "plugins.security.authcz.admin_dn",
                Arrays.asList(TEST_CERTIFICATES.getAdminDNs()),
                "plugins.security.unsupported.inject_user.enabled",
                true,
                "plugins.security.authcz.rest_impersonation_user.grpc_impersonating_user",
                Arrays.asList("grpc_search_user", "grpc_user")
            )
        )
        .plugin(
            // Add GrpcPlugin
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
            // Override the default security plugin with one that declares extension relationship
            new PluginInfo(
                OpenSearchSecurityPlugin.class.getName(),
                "classpath plugin",
                "NA",
                Version.CURRENT,
                "21",
                OpenSearchSecurityPlugin.class.getName(),
                null,
                List.of("org.opensearch.transport.grpc.GrpcPlugin"), // Extends GrpcPlugin
                false
            )
        )
        .anonymousAuth(false)
        .users(GRPC_INDEX_USER, GRPC_INDEX_USER_NO_MAPPING, GRPC_SEARCH_USER, GRPC_IMPERSONATING_USER)
        .roles(GRPC_INDEX_ROLE, GRPC_INDEX_ROLE_NO_MAPPING, GRPC_SEARCH_ROLE)
        .rolesMapping(
            new TestSecurityConfig.RoleMapping(GRPC_INDEX_ROLE.getName()).backendRoles("grpc_index_role"),
            new TestSecurityConfig.RoleMapping(GRPC_INDEX_ROLE_NO_MAPPING.getName()).backendRoles("grpc_limited_role"),
            new TestSecurityConfig.RoleMapping(GRPC_SEARCH_ROLE.getName()).backendRoles("grpc_search_role")
        )
        .authc(JWT_AUTH_DOMAIN)
        .authc(BASIC_AUTH_DOMAIN)
        .build();

    @Test
    public void testJwtAuthorizedUser() throws Exception {
        String jwtToken = createValidJwtToken("grpc_user", "grpc_index_role");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor jwtInterceptor = createHeaderInterceptor(Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, jwtInterceptor);
            BulkResponse bulkResp = doBulk(channelWithAuth, "test-grpc-index", 2);
            assertNotNull(bulkResp);
            assertFalse(bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testJwtAuthorizedUserIsAdmin() throws Exception {
        // Use the actual admin DN from the certificate as the JWT username
        String adminDN = "CN=kirk,OU=client,O=client,L=test,C=de";
        String jwtToken = createValidJwtToken(adminDN, "grpc_index_role");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor jwtInterceptor = createHeaderInterceptor(Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, jwtInterceptor);

            try {
                doBulk(channelWithAuth, "test-fake-admin", 2);
                fail("Expected authentication failure due to invalid JWT signature");
            } catch (StatusRuntimeException e) {
                assertEquals("Expected PERMISSION_DENIED status", Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
                assertEquals(
                    "Expected specific error message",
                    "Cannot authenticate user because admin user is not permitted to login via HTTP",
                    e.getStatus().getDescription()
                );
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testJwtUserMissingMappingPermission() throws Exception {
        String jwtToken = createValidJwtToken("grpc_limited_user", "grpc_limited_role");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor jwtInterceptor = createHeaderInterceptor(Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, jwtInterceptor);

            BulkResponse bulkResp = doBulk(channelWithAuth, "test-limited-index", 2);
            assertNotNull(bulkResp);
            assertTrue(bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());

            // Expect missing "put mapping" permissions
            String errorMessage = bulkResp.getItems(0).getIndex().getError().getReason();
            assertTrue("Expected mapping permission error", errorMessage.contains("indices:admin/mapping/put"));
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testJwtInvalidSignature() throws Exception {
        String jwtToken = createInvalidSignatureJwtToken("grpc_user", "grpc_index_role");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor jwtInterceptor = createHeaderInterceptor(Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, jwtInterceptor);

            try {
                doBulk(channelWithAuth, "test-invalid-sig", 2);
                fail("Expected authentication failure due to invalid JWT signature");
            } catch (StatusRuntimeException e) {
                assertEquals("Expected UNAUTHENTICATED status", Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
                assertEquals("Expected specific error message", AUTH_FINALLY_FAILED, e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testJwtWrongClaims() throws Exception {
        String jwtToken = createWrongClaimsJwtToken("grpc_user", "grpc_index_role");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor jwtInterceptor = createHeaderInterceptor(Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, jwtInterceptor);

            try {
                doBulk(channelWithAuth, "test-wrong-claims", 2);
                fail("Expected authentication failure due to wrong JWT claims");
            } catch (StatusRuntimeException e) {
                assertEquals("Expected UNAUTHENTICATED status", Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
                assertEquals("Expected specific error message", AUTH_FINALLY_FAILED, e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testJwtWithStandardAuthorizationHeader() throws Exception {
        String jwtToken = createValidJwtToken("grpc_user", "grpc_index_role");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            // Test with standard Authorization header - should fail since we configured custom jwt-auth header
            ClientInterceptor jwtInterceptor = createHeaderInterceptor(Map.of("Authorization", "Bearer " + jwtToken));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, jwtInterceptor);

            try {
                doBulk(channelWithAuth, "test-auth-header", 2);
                fail("Expected authentication failure - Authorization header not configured for JWT");
            } catch (StatusRuntimeException e) {
                assertEquals("Expected UNAUTHENTICATED status", Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
                assertEquals("Expected specific error message", AUTH_FINALLY_FAILED, e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testJwtNoToken() throws Exception {
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            // No JWT token provided - should fail authentication
            try {
                doBulk(channel, "test-no-token", 2);
                fail("Expected authentication failure - no JWT token provided");
            } catch (StatusRuntimeException e) {
                assertEquals("Expected UNAUTHENTICATED status", Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
                assertEquals("Expected specific error message", AUTH_FINALLY_FAILED, e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testBadSecurityHeaderInMetadata() throws Exception {
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor badHeaderInterceptor = createHeaderInterceptor(Map.of("_opendistro_security_user", "malicious_user"));
            Channel channelWithBadHeader = io.grpc.ClientInterceptors.intercept(channel, badHeaderInterceptor);

            try {
                doBulk(channelWithBadHeader, "test-bad-header", 2);
                fail("Expected rejection due to bad security header");
            } catch (StatusRuntimeException e) {
                assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
                assertEquals("Illegal security header in gRPC request", e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testJwtTenantSelectionRejected() throws Exception {
        String jwtToken = createValidJwtToken("grpc_user", "grpc_index_role");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor jwtInterceptor = createHeaderInterceptor(
                Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken, "securitytenant", "test_tenant")
            );
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, jwtInterceptor);

            try {
                doBulk(channelWithAuth, "test-tenant-rejected", 2);
                fail("Expected rejection - tenant selection not supported");
            } catch (StatusRuntimeException e) {
                assertEquals(Status.Code.INVALID_ARGUMENT, e.getStatus().getCode());
                assertEquals("Tenant selection not supported in gRPC", e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testBasicAuthRejectedForGrpc() throws Exception {
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            String credentials = Base64.getEncoder().encodeToString("grpc_user:password".getBytes());
            ClientInterceptor basicAuthInterceptor = createHeaderInterceptor(Map.of("Authorization", "Basic " + credentials));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, basicAuthInterceptor);

            try {
                doBulk(channelWithAuth, "test-basic-auth-header", 2);
                fail("Expected rejection - basic auth not supported");
            } catch (StatusRuntimeException e) {
                assertEquals(Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
                assertEquals(AUTH_FINALLY_FAILED, e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testUserInjectionWithNoAuthUser() throws Exception {
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor injectionInterceptor = createHeaderInterceptor(
                Map.of("test-user-injection", "injected_grpc_index_user|grpc_index_role")
            );
            Channel channelWithInjection = io.grpc.ClientInterceptors.intercept(channel, injectionInterceptor);

            BulkResponse bulkResp = doBulk(channelWithInjection, "test-user-injection", 2);
            assertNotNull(bulkResp);
            assertFalse(bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testLimitedUserInjectionWithNoAuthUser() throws Exception {
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor injectionInterceptor = createHeaderInterceptor(
                Map.of("test-user-injection", "injected_limited_user|grpc_limited_role")
            );
            Channel channelWithInjection = io.grpc.ClientInterceptors.intercept(channel, injectionInterceptor);

            BulkResponse bulkResp = doBulk(channelWithInjection, "test-limited-injection", 2);
            assertNotNull(bulkResp);
            assertTrue(bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());

            String errorMessage = bulkResp.getItems(0).getIndex().getError().getReason();
            assertTrue("Expected mapping permission error", errorMessage.contains("indices:admin/mapping/put"));
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testLimitedUserInjectionWithValidAuthUser() throws Exception {
        String jwtToken = createValidJwtToken("grpc_user", "grpc_index_role");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor interceptor = createHeaderInterceptor(
                Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken, "test-user-injection", "injected_limited_user|grpc_limited_role")
            );
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, interceptor);

            BulkResponse bulkResp = doBulk(channelWithAuth, "test-injection-override", 2);
            assertNotNull(bulkResp);
            assertTrue(bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());

            String errorMessage = bulkResp.getItems(0).getIndex().getError().getReason();
            assertTrue("Expected mapping permission error", errorMessage.contains("indices:admin/mapping/put"));
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testValidUserInjectionWithLimitedAuthUser() throws Exception {
        String jwtToken = createValidJwtToken("grpc_get_user", "grpc_get_role");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor interceptor = createHeaderInterceptor(
                Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken, "test-user-injection", "injected_grpc_index_user|grpc_index_role")
            );
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, interceptor);

            BulkResponse bulkResp = doBulk(channelWithAuth, "test-valid-injection", 2);
            assertNotNull(bulkResp);
            assertFalse(bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testUserImpersonation() throws Exception {
        String jwtToken = createValidJwtToken("grpc_impersonating_user", "");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor interceptor = createHeaderInterceptor(
                Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken, "opendistro_security_impersonate_as", "grpc_user")
            );
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, interceptor);

            BulkResponse bulkResp = doBulk(channelWithAuth, "test-impersonation", 2);
            assertNotNull(bulkResp);
            assertFalse(bulkResp.getErrors());
            assertEquals(2, bulkResp.getItemsCount());
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testUserImpersonationInsufficientPermissions() throws Exception {
        String jwtToken = createValidJwtToken("grpc_impersonating_user", "");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor interceptor = createHeaderInterceptor(
                Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken, "opendistro_security_impersonate_as", "grpc_search_user")
            );
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, interceptor);

            try {
                doBulk(channelWithAuth, "test-impersonation-denied", 2);
                fail("Expected permission denied - search user cannot perform bulk operations");
            } catch (StatusRuntimeException e) {
                assertEquals("Expected PERMISSION_DENIED status", Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
                assertNotNull(e.getStatus().getDescription());
                assertTrue("Expected bulk permission error", e.getStatus().getDescription().contains("indices:data/write/bulk"));
            }
        } finally {
            channel.shutdown();
        }
    }
}
