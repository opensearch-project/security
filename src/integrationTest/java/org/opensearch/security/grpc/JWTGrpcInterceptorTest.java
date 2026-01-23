/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.grpc;

import java.security.KeyPair;
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

    // JWT claims/keys
    public static final List<String> CLAIM_USERNAME = List.of("preferred-username");
    public static final List<String> CLAIM_ROLES = List.of("backend-user-roles");
    public static final String JWT_AUTH_HEADER = "jwt-auth";
    private static final KeyPair KEY_PAIR = Keys.keyPairFor(SignatureAlgorithm.RS256);
    private static final String PUBLIC_KEY = new String(Base64.getEncoder().encode(KEY_PAIR.getPublic().getEncoded()), US_ASCII);

    // Role with full bulk index permissions
    static final TestSecurityConfig.Role GRPC_INDEX_ROLE = new TestSecurityConfig.Role("grpc_index_role").clusterPermissions(
        "indices:data/write/bulk*"
    ).indexPermissions("indices:data/write/bulk*", "indices:admin/mapping/put", "indices:admin/create", "indices:data/write/index").on("*");
    static final TestSecurityConfig.User GRPC_INDEX_USER = new TestSecurityConfig.User("grpc_user").roles(GRPC_INDEX_ROLE);

    // Role missing mapping permission - Cannot create indices
    static final TestSecurityConfig.Role GRPC_LIMITED_ROLE = new TestSecurityConfig.Role("grpc_limited_role").clusterPermissions(
        "indices:data/write/bulk*"
    ).indexPermissions("indices:data/write/bulk*", "indices:admin/create", "indices:data/write/index").on("*");
    static final TestSecurityConfig.User GRPC_LIMITED_USER = new TestSecurityConfig.User("grpc_limited_user").roles(GRPC_LIMITED_ROLE);

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

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .certificates(TEST_CERTIFICATES)
        .nodeSettings(SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS)
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
        .users(GRPC_INDEX_USER, GRPC_LIMITED_USER)
        .roles(GRPC_INDEX_ROLE, GRPC_LIMITED_ROLE)
        .rolesMapping(
            new TestSecurityConfig.RoleMapping(GRPC_INDEX_ROLE.getName()).backendRoles("grpc_index_role"),
            new TestSecurityConfig.RoleMapping(GRPC_LIMITED_ROLE.getName()).backendRoles("grpc_limited_role")
        )
        .authc(JWT_AUTH_DOMAIN)
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
                assertEquals("Expected specific error message", "gRPC authentication failed", e.getStatus().getDescription());
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
                assertEquals("Expected specific error message", "gRPC authentication failed", e.getStatus().getDescription());
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
                assertEquals("Expected specific error message", "gRPC authentication failed", e.getStatus().getDescription());
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
                assertEquals("Expected specific error message", "gRPC authentication failed", e.getStatus().getDescription());
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
}
