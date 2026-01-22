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

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.jsonwebtoken.Jwts;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.protobufs.BulkResponse;
import org.opensearch.protobufs.BulkRequest;
import org.opensearch.protobufs.BulkRequestBody;
import org.opensearch.protobufs.IndexOperation;
import org.opensearch.protobufs.OperationContainer;
import org.opensearch.protobufs.Refresh;
import org.opensearch.protobufs.services.DocumentServiceGrpc;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.JwtConfigBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.grpc.GrpcPlugin;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.opensearch.security.grpc.GrpcHelpers.SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.createHeaderInterceptor;
import static org.opensearch.security.grpc.GrpcHelpers.doBulk;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.opensearch.security.grpc.GrpcHelpers.secureChannel;

public class JWTGrpcInterceptorTest {

    // JWT claims/keys
    public static final List<String> CLAIM_USERNAME = List.of("preferred-username");
    public static final List<String> CLAIM_ROLES = List.of("backend-user-roles");
    public static final String JWT_AUTH_HEADER = "jwt-auth";
    private static final KeyPair KEY_PAIR = Keys.keyPairFor(SignatureAlgorithm.RS256);
    private static final String PUBLIC_KEY = new String(Base64.getEncoder().encode(KEY_PAIR.getPublic().getEncoded()), US_ASCII);

    // bulk write cluster permissions
    static final TestSecurityConfig.Role GRPC_INDEX_ROLE = new TestSecurityConfig.Role("grpc_index_role")
            .clusterPermissions("indices:data/write/bulk*")
            .indexPermissions("indices:data/write/bulk*", "indices:admin/mapping/put", "indices:admin/create", "indices:data/write/index").on("*");
    static final TestSecurityConfig.User GRPC_INDEX_USER = new TestSecurityConfig.User("grpc_user").roles(GRPC_INDEX_ROLE);

    /**
     * @param username OpenSearch user to authenticate.
     * @param roles OpenSearch backend roles.
     */
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

    public static final TestSecurityConfig.AuthcDomain JWT_AUTH_DOMAIN = new TestSecurityConfig.AuthcDomain(
        "jwt",
        2
    ).jwtHttpAuthenticator(
        new JwtConfigBuilder().jwtHeader(JWT_AUTH_HEADER)
            .signingKey(List.of(PUBLIC_KEY))
            .subjectKey(CLAIM_USERNAME)
            .rolesKey(CLAIM_ROLES)
    ).backend("noop");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder()
        .clusterManager(ClusterManager.SINGLENODE)
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
                    List.of("org.opensearch.transport.grpc.GrpcPlugin"), // Extends GrpcPlugin by class name
                    false
            )
        ).anonymousAuth(false)
        .users(GRPC_INDEX_USER)
        .roles(GRPC_INDEX_ROLE)
        .rolesMapping(new TestSecurityConfig.RoleMapping(GRPC_INDEX_ROLE.getName()).backendRoles("grpc_index_role"))
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
}
