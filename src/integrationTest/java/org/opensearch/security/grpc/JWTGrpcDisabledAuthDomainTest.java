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
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import io.grpc.Channel;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.JwtConfigBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.grpc.GrpcPlugin;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.Assert.fail;
import static org.opensearch.security.grpc.GrpcHelpers.GRPC_INDEX_ROLE;
import static org.opensearch.security.grpc.GrpcHelpers.GRPC_INDEX_USER;
import static org.opensearch.security.grpc.GrpcHelpers.SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.createHeaderInterceptor;
import static org.opensearch.security.grpc.GrpcHelpers.doBulk;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.opensearch.security.grpc.GrpcHelpers.secureChannel;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class JWTGrpcDisabledAuthDomainTest {

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

    // Basic auth domain to ensure security plugin initializes (must have at least 1 auth domain/auth path)
    public static final TestSecurityConfig.AuthcDomain BASIC_AUTH_DOMAIN = new TestSecurityConfig.AuthcDomain("basic", 1, true)
        .httpAuthenticator("basic")
        .backend("internal");

    // JWT auth domain with http_enabled: false
    public static final TestSecurityConfig.AuthcDomain JWT_AUTH_DOMAIN_DISABLED = new TestSecurityConfig.AuthcDomain("jwt", 2, false)
        .jwtHttpAuthenticator(
            new JwtConfigBuilder().jwtHeader(JWT_AUTH_HEADER).signingKey(List.of(PUBLIC_KEY)).subjectKey(CLAIM_USERNAME).rolesKey(CLAIM_ROLES)
        )
        .backend("noop");

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
        .rolesMapping(
            new TestSecurityConfig.RoleMapping(GRPC_INDEX_ROLE.getName()).backendRoles("grpc_index_role")
        )
        .authc(BASIC_AUTH_DOMAIN)
        .authc(JWT_AUTH_DOMAIN_DISABLED)
        .build();

    /*
    This test mirrors a valid JWT token on a properly configured test cluster with the exception that the jwt auth
    domain simulates the following setting:

    config:
      dynamic:
        authc:
          jwt_auth_domain:
            http_enabled: false

    These settings are configured and loaded by the dynamic config model but here we disable JWT through the test framework instead.
    The test verifies that when http_enabled is set to false, JWT authentication fails for gRPC requests.
     */
    @Test
    public void testHttpEnabledImpactsGrpcUser() throws Exception {
        String jwtToken = createValidJwtToken("grpc_user", "grpc_index_role");
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));

        try {
            ClientInterceptor jwtInterceptor = createHeaderInterceptor(Map.of(JWT_AUTH_HEADER, "Bearer " + jwtToken));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, jwtInterceptor);

            try {
                doBulk(channelWithAuth, "test-grpc-index", 2);
                fail("Expected authentication failure due to JWT auth domain disabled");
            } catch (StatusRuntimeException e) {
                assertEquals("Expected UNAUTHENTICATED status", Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
                assertEquals("Expected specific error message", "Authentication finally failed", e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }
}
