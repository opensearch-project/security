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
import java.util.List;

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

import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.opensearch.security.grpc.GrpcHelpers.SINGLE_NODE_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.BASIC_AUTH_DOMAIN_ORDER;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

public class JWTGrpcInterceptorTest {

    public static final List<String> CLAIM_USERNAME = List.of("preferred-username");
    public static final List<String> CLAIM_ROLES = List.of("backend-user-roles");
    public static final String JWT_AUTH_HEADER = "jwt-auth";

    private static final KeyPair KEY_PAIR = Keys.keyPairFor(SignatureAlgorithm.RS256);
    private static final String PUBLIC_KEY = new String(Base64.getEncoder().encode(KEY_PAIR.getPublic().getEncoded()), US_ASCII);

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    public static final TestSecurityConfig.AuthcDomain JWT_AUTH_DOMAIN = new TestSecurityConfig.AuthcDomain(
        "jwt",
        BASIC_AUTH_DOMAIN_ORDER - 1
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
        .nodeSettings(SINGLE_NODE_GRPC_TRANSPORT_SETTINGS)
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
        .users(ADMIN_USER)
        .authc(JWT_AUTH_DOMAIN)
        .build();

    @Test
    public void testGrpcInterceptorBackendRegistryInjection() {
        System.out.println("Test passes with JWT auth configured cluster (Cluster starts and stops)");
    }
}
