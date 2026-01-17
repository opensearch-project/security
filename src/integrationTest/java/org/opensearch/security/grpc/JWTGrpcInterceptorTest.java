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
import static org.opensearch.security.grpc.GrpcHelpers.SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.opensearch.security.grpc.GrpcHelpers.secureChannel;
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
        .users(ADMIN_USER)
        .authc(JWT_AUTH_DOMAIN)
        .build();

    @Test
    public void testGrpcInterceptorBackendRegistryInjection() {
        System.out.println("Test passes with JWT auth configured cluster (Cluster starts and stops)");
    }

    @Test
    public void testJwtTokenInGrpcRequest() throws Exception {
        // Create a valid JWT token
        String jwtToken = createValidJwtToken("john.doe", "admin", "user");
        System.out.println("Created JWT token: " + jwtToken);

        // Print JWT components
        String[] parts = jwtToken.split("\\.");
        System.out.println("JWT Header: " + new String(Base64.getUrlDecoder().decode(parts[0])));
        System.out.println("JWT Payload: " + new String(Base64.getUrlDecoder().decode(parts[1])));
        System.out.println("JWT Signature: " + parts[2]);

        // Initialize gRPC channel
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));

        try {
            // Create a client interceptor to add JWT header
            ClientInterceptor jwtInterceptor = new ClientInterceptor() {
                @Override
                public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
                        MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
                    return new ClientCall<ReqT, RespT>() {
                        private final ClientCall<ReqT, RespT> delegate = next.newCall(method, callOptions);

                        @Override
                        public void start(Listener<RespT> responseListener, Metadata headers) {
                            // Add JWT token to headers
                            Metadata.Key<String> authKey = Metadata.Key.of(JWT_AUTH_HEADER, Metadata.ASCII_STRING_MARSHALLER);
                            headers.put(authKey, "Bearer " + jwtToken);
                            System.out.println("Client: Added JWT header: " + JWT_AUTH_HEADER + " = Bearer " + jwtToken.substring(0, 20) + "...");
                            delegate.start(responseListener, headers);
                        }

                        @Override
                        public void sendMessage(ReqT message) { delegate.sendMessage(message); }

                        @Override
                        public void halfClose() { delegate.halfClose(); }

                        @Override
                        public void cancel(String message, Throwable cause) { delegate.cancel(message, cause); }

                        @Override
                        public void request(int numMessages) { delegate.request(numMessages); }
                    };
                }
            };

            // Create channel with JWT interceptor
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, jwtInterceptor);

            // Send bulk request with JWT token
            System.out.println("Sending bulk request with JWT token...");
            doBulkWithChannel(channelWithAuth, "test-index", 1);
            System.out.println("Bulk request completed - JWT token should have been processed by SecurityGrpcFilter");

        } finally {
            channel.shutdown();
        }
    }

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

    private void doBulkWithChannel(Channel channel, String index, long numDocs) {
        BulkRequest.Builder requestBuilder = BulkRequest.newBuilder().setRefresh(Refresh.REFRESH_TRUE).setIndex(index);
        for (int i = 0; i < numDocs; i++) {
            String docBody = """
                {
                    "field": "doc %d body"
                }
                """.formatted(i);
            IndexOperation.Builder indexOp = IndexOperation.newBuilder().setXId(String.valueOf(i));
            OperationContainer.Builder opCont = OperationContainer.newBuilder().setIndex(indexOp);
            BulkRequestBody requestBody = BulkRequestBody.newBuilder()
                    .setOperationContainer(opCont)
                    .setObject(com.google.protobuf.ByteString.copyFromUtf8(docBody))
                    .build();
            requestBuilder.addBulkRequestBody(requestBody);
        }
        DocumentServiceGrpc.DocumentServiceBlockingStub stub = DocumentServiceGrpc.newBlockingStub(channel);
        stub.bulk(requestBuilder.build());
    }
}
