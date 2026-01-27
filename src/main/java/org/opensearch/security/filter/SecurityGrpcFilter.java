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

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.ssl.util.SSLRequestHelper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HTTPHelper;
import org.opensearch.security.user.User;
import org.opensearch.transport.grpc.spi.GrpcInterceptorProvider;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;

public class SecurityGrpcFilter implements GrpcInterceptorProvider {
    private static final Logger log = LogManager.getLogger(SecurityGrpcFilter.class);

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

            @Override
            public ServerInterceptor getInterceptor() {
                return new JwtGrpcInterceptor(
                    threadContext,
                    OpenSearchSecurityPlugin.GuiceHolder.getBackendRegistry(),
                    OpenSearchSecurityPlugin.GuiceHolder.getAuditLog()
                );
            }
        });
    }

    /**
     * gRPC interceptor that extracts JWT tokens from headers and authenticates them against the BackendRegistry.
     */
    private static class JwtGrpcInterceptor implements ServerInterceptor {
        private final ThreadContext threadContext;
        private final BackendRegistry backendRegistry;
        private final AuditLog auditLog;

        public JwtGrpcInterceptor(ThreadContext threadContext, BackendRegistry backendRegistry, AuditLog auditLog) {
            this.threadContext = threadContext;
            this.backendRegistry = backendRegistry;
            this.auditLog = auditLog;
        }

        @Override
        public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> serverCall,
            Metadata metadata,
            ServerCallHandler<ReqT, RespT> serverCallHandler
        ) {
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
            ServerCallHandler<ReqT, RespT> serverCallHandler
        ) {
            final GrpcRequestChannel requestChannel = new GrpcRequestChannel(serverCall, metadata);

            try {
                if (HTTPHelper.containsBadHeader(requestChannel)) {
                    auditLog.logBadHeaders(requestChannel);
                    serverCall.close(Status.PERMISSION_DENIED.withDescription("Illegal security header in gRPC request"), new Metadata());
                    return new ServerCall.Listener<>() {
                    };
                }

                if (SSLRequestHelper.containsBadHeader(threadContext, ConfigConstants.OPENDISTRO_SECURITY_CONFIG_PREFIX)) {
                    auditLog.logBadHeaders(requestChannel);
                    serverCall.close(Status.PERMISSION_DENIED.withDescription("Illegal security header in thread context"), new Metadata());
                    return new ServerCall.Listener<>() {
                    };
                }

                /*
                 Authenticate user - Authenticated users are stashed in the thread context under:
                 ConfigConstants.OPENDISTRO_SECURITY_USER
                 Authorization handled by the node-to-node transport layer given the authenticated user.
                 */
                if (!backendRegistry.authenticate(requestChannel)) {
                    if (requestChannel.getQueuedResponse().isPresent()) {
                        // Send error response and close call
                        serverCall.close(requestChannel.getQueuedResponseGrpcStatus(), new Metadata());
                    } else {
                        // Authentication failed without specific error
                        serverCall.close(Status.UNAUTHENTICATED, new Metadata());
                    }
                    return new ServerCall.Listener<>() {
                    };
                }

                // Origin used in audit logging
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, AuditLog.Origin.GRPC.toString());

                // Request may be rejected during authentication without throwing exception - Check and reject here
                if (requestChannel.getQueuedResponse().isPresent()) {
                    serverCall.close(Status.PERMISSION_DENIED, new Metadata());
                    return new ServerCall.Listener<>() {
                    };
                }

                // Log successful authentication for audit
                final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                if (user != null) {
                    auditLog.logSucceededLogin(user.getName(), false, null, requestChannel);
                }

                // Caller was authorized - Proceed with request
                return serverCallHandler.startCall(serverCall, metadata);
            } catch (Exception e) {
                log.error("Unexpected authentication error", e);
                serverCall.close(
                    io.grpc.Status.INTERNAL.withDescription("Unexpected authentication error: " + e.getMessage()),
                    new Metadata()
                );
                return new ServerCall.Listener<>() {
                };
            }
        }
    }
}
