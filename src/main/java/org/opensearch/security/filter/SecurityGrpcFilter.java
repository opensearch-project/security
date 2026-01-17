/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.filter;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.transport.grpc.spi.GrpcInterceptorProvider;

import java.util.List;
import java.util.regex.Pattern;

public class SecurityGrpcFilter implements GrpcInterceptorProvider {

    private static final Pattern BASIC = Pattern.compile("^\\s*Basic\\s.*", Pattern.CASE_INSENSITIVE);
    private static final String BEARER = "bearer ";
    private static final String AUTHORIZATION_HEADER = "authorization";
    private static final String JWT_AUTH_HEADER = "jwt-auth";

    // gRPC metadata keys (case-insensitive)
    private static final Metadata.Key<String> AUTHORIZATION_KEY =
        Metadata.Key.of(AUTHORIZATION_HEADER, Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> JWT_AUTH_KEY =
        Metadata.Key.of(JWT_AUTH_HEADER, Metadata.ASCII_STRING_MARSHALLER);

    static {
        System.out.println("SecurityGrpcFilter - class loaded by ClassLoader: " + SecurityGrpcFilter.class.getClassLoader());
    }

    public SecurityGrpcFilter() {
        // Default constructor for plugin extension framework
    }

    @Override
    public List<OrderedGrpcInterceptor> getOrderedGrpcInterceptors(ThreadContext threadContext) {
        return List.of(new OrderedGrpcInterceptor() {

            @Override
            public int order() {
                return 0;
            }

            @Override
            public ServerInterceptor getInterceptor() {
                return new JwtGrpcInterceptor(threadContext);
            }
        });
    }

    /**
     * gRPC interceptor that extracts JWT tokens from headers
     */
    private static class JwtGrpcInterceptor implements ServerInterceptor {
        private final ThreadContext threadContext;

        public JwtGrpcInterceptor(ThreadContext threadContext) {
            this.threadContext = threadContext;
        }

        @Override
        public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
                ServerCall<ReqT, RespT> serverCall,
                Metadata metadata,
                ServerCallHandler<ReqT, RespT> serverCallHandler) {

            System.out.println("SecurityGrpcFilter - Interceptor called for method: " + serverCall.getMethodDescriptor().getFullMethodName());

            // Access BackendRegistry through GuiceHolder
            BackendRegistry backendRegistry = OpenSearchSecurityPlugin.GuiceHolder.getBackendRegistry();
            if (backendRegistry != null) {
                System.out.println("SecurityGrpcFilter - BackendRegistry accessed successfully, isInitialized: " + backendRegistry.isInitialized());
            } else {
                System.out.println("SecurityGrpcFilter - BackendRegistry is null");
            }

            // Extract JWT token from gRPC metadata
            String jwtToken = extractJwtToken(metadata);

            System.out.println("SecurityGrpcFilter - JWT extraction result: " + (jwtToken != null ? "SUCCESS" : "FAILED"));
            if (jwtToken != null) {
                System.out.println("SecurityGrpcFilter - JWT token extracted: " + maskToken(jwtToken));
                
                // Print JWT token components
                printJwtComponents(jwtToken);

                // Store in ThreadContext for potential use by security components
                threadContext.putHeader(AUTHORIZATION_HEADER, "Bearer " + jwtToken);
                System.out.println("SecurityGrpcFilter - JWT token stored in ThreadContext");
            } else {
                System.out.println("SecurityGrpcFilter - No JWT token found in gRPC headers");
            }

            // Log all headers for debugging
            logAllHeaders(metadata);

            return serverCallHandler.startCall(serverCall, metadata);
        }

        private String extractJwtToken(Metadata metadata) {
            // Try jwt-auth header first
            String authHeader = metadata.get(JWT_AUTH_KEY);
            
            // Fallback to authorization header
            if (authHeader == null || authHeader.isEmpty()) {
                authHeader = metadata.get(AUTHORIZATION_KEY);
            }

            if (authHeader == null || authHeader.isEmpty()) {
                return null;
            }

            // Skip Basic auth
            if (BASIC.matcher(authHeader).matches()) {
                return null;
            }

            // Extract Bearer token
            final int index = authHeader.toLowerCase().indexOf(BEARER);
            if (index > -1) {
                return authHeader.substring(index + BEARER.length()).trim();
            }

            return null;
        }

        private void logAllHeaders(Metadata metadata) {
            System.out.println("SecurityGrpcFilter - All gRPC headers:");
            for (String key : metadata.keys()) {
                if (key.endsWith("-bin")) {
                    System.out.println("  " + key + ": [binary data]");
                } else {
                    String value = metadata.get(Metadata.Key.of(key, Metadata.ASCII_STRING_MARSHALLER));
                    System.out.println("  " + key + ": " + (key.toLowerCase().contains("auth") ? maskToken(value) : value));
                }
            }
        }

        private String maskToken(String token) {
            if (token == null || token.length() < 10) {
                return "[masked]";
            }
            return token.substring(0, 10) + "...[" + (token.length() - 10) + " more chars]";
        }

        private void printJwtComponents(String jwtToken) {
            try {
                String[] parts = jwtToken.split("\\.");
                if (parts.length == 3) {
                    System.out.println("SecurityGrpcFilter - JWT Components:");
                    System.out.println("  Header: " + new String(java.util.Base64.getUrlDecoder().decode(parts[0])));
                    System.out.println("  Payload: " + new String(java.util.Base64.getUrlDecoder().decode(parts[1])));
                    System.out.println("  Signature: " + parts[2].substring(0, Math.min(10, parts[2].length())) + "...");
                } else {
                    System.out.println("SecurityGrpcFilter - Invalid JWT format (expected 3 parts, got " + parts.length + ")");
                }
            } catch (Exception e) {
                System.out.println("SecurityGrpcFilter - Error parsing JWT components: " + e.getMessage());
            }
        }
    }
}
