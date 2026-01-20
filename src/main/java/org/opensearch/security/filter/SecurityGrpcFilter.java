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
import io.grpc.Status;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
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
        // Empty constructor initialized by extensible plugin framework
    }

    @Override
    public List<OrderedGrpcInterceptor> getOrderedGrpcInterceptors(ThreadContext threadContext) {
        return List.of(new OrderedGrpcInterceptor() {

            @Override
            public int order() {
                return 0;
            }

            /**
             * Construct gRPC interceptors provided by this plugin.
             * GuiceHolder is used over the more direct @Inject here due to how @inject interacts with the extensible
             * plugin framework. Extensible plugins are initialized via SPIClassIterator which interferes with Guice's
             * ability to build a dependency graph as it obfuscates when/where the SecurityGrpcFilter will be created.
             */
            @Override
            public ServerInterceptor getInterceptor() {
                return new JwtGrpcInterceptor(threadContext, OpenSearchSecurityPlugin.GuiceHolder.getBackendRegistry());
            }
        });
    }

    /**
     * gRPC interceptor that extracts JWT tokens from headers and authenticates them against the BackendRegistry.
     */
    private static class JwtGrpcInterceptor implements ServerInterceptor {
        private final ThreadContext threadContext;
        private final BackendRegistry backendRegistry;

        public JwtGrpcInterceptor(ThreadContext threadContext, BackendRegistry backendRegistry) {
            this.threadContext = threadContext;
            this.backendRegistry = backendRegistry;
        }

        @Override
        public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
                ServerCall<ReqT, RespT> serverCall,
                Metadata metadata,
                ServerCallHandler<ReqT, RespT> serverCallHandler) {

            return handleCall(serverCall, metadata, serverCallHandler);
        }

        /**
         * Main gRPC call handler implementing the high level security flow.
         * This handler mirrors the behavior of SecurityRestFilter.handleRequest to maintain parity between protocols.
         *
         * Notable features which are not included in the gRPC path include:
         * 1. Thread context restoration (Pipelining/Multiplexing inherently handled with gRPC and no pre-authentication netty handlers exist).
         * 2. Unconsumed params check is unnecessary as gRPC has no query params.
         * 3. Request filtering is unsupported and counterproductive for binary formats.
         * 4. Superuser authentication not supported over gRPC.
         * 5. Allowlist checks are not implemented for gRPC in this version.
         */
        private <ReqT, RespT> ServerCall.Listener<ReqT> handleCall(
                ServerCall<ReqT, RespT> serverCall,
                Metadata metadata,
                ServerCallHandler<ReqT, RespT> serverCallHandler) {

            // Create request channel
            final GrpcRequestChannel requestChannel = new GrpcRequestChannel(serverCall, metadata);

            try {
                // Authenticate request
                if (!backendRegistry.gRPCauthenticate(requestChannel)) {
                    if (requestChannel.getQueuedResponse().isPresent()) {
                        // Send error response and close call
                        serverCall.close(mapToGrpcStatus(requestChannel.getQueuedResponse().get().getStatus()), new Metadata());
                        return new ServerCall.Listener<>() {};
                    }
                }

                // Authorize request
                final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                // authorizeRequest(requestChannel, user);
                if (requestChannel.getQueuedResponse().isPresent()) {
                    serverCall.close(Status.PERMISSION_DENIED, new Metadata());
                    return new ServerCall.Listener<>() {};
                }

                // Caller was authorized - Proceed with request
                return serverCallHandler.startCall(serverCall, metadata);
            } catch (Exception e) {
                // Handle unexpected exceptions
                serverCall.close(io.grpc.Status.INTERNAL.withDescription("Authentication error: " + e.getMessage()), new Metadata());
                return new ServerCall.Listener<>() {};
            }
        }

        /**
         * Map HTTP status codes to gRPC Status
         * TODO: Move this to GrpcRequestChannel implementation. Add reason to error response.
         */
        private io.grpc.Status mapToGrpcStatus(int httpStatus) {
            return switch (httpStatus) {
                case 400 -> Status.INVALID_ARGUMENT;
                case 401 -> Status.UNAUTHENTICATED;
                case 403 -> Status.PERMISSION_DENIED;
                case 404 -> Status.NOT_FOUND;
                case 429 -> Status.RESOURCE_EXHAUSTED;
                case 500 -> Status.INTERNAL;
                case 503 -> Status.UNAVAILABLE;
                default -> Status.UNKNOWN;
            };
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
