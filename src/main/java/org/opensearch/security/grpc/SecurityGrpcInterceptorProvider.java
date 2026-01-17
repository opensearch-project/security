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

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.transport.grpc.spi.GrpcInterceptorProvider;

import io.grpc.ServerInterceptor;

/**
 * SPI implementation that provides security interceptors for gRPC transport.
 * <p>
 * This provider creates a {@link SecurityGrpcInterceptor} that extracts authentication
 * credentials from gRPC metadata headers and stores them in the OpenSearch ThreadContext
 * for processing by the security subsystem.
 * <p>
 * The interceptor is registered with a low order value (high priority) to ensure it runs
 * early in the interceptor chain, before other interceptors that may depend on the
 * authenticated user context.
 * <p>
 * This class is discovered via Java SPI (ServiceLoader) by the transport-grpc module.
 */
public class SecurityGrpcInterceptorProvider implements GrpcInterceptorProvider {

    private static final Logger log = LogManager.getLogger(SecurityGrpcInterceptorProvider.class);

    /**
     * Order value for the security interceptor.
     * Using a very low value to ensure security is evaluated first.
     */
    public static final int SECURITY_INTERCEPTOR_ORDER = Integer.MIN_VALUE;

    /**
     * Creates a new SecurityGrpcInterceptorProvider.
     * This constructor is called by Java ServiceLoader.
     */
    public SecurityGrpcInterceptorProvider() {
        log.info("SecurityGrpcInterceptorProvider initialized");
    }

    @Override
    public List<OrderedGrpcInterceptor> getOrderedGrpcInterceptors(ThreadContext threadContext) {
        log.debug("Creating security gRPC interceptors with ThreadContext");

        SecurityGrpcInterceptor securityInterceptor = new SecurityGrpcInterceptor(threadContext);

        OrderedGrpcInterceptor orderedInterceptor = new SecurityOrderedGrpcInterceptor(securityInterceptor, SECURITY_INTERCEPTOR_ORDER);

        return List.of(orderedInterceptor);
    }

    /**
     * Implementation of OrderedGrpcInterceptor that wraps the SecurityGrpcInterceptor
     * with an order value for execution priority.
     */
    private static class SecurityOrderedGrpcInterceptor implements OrderedGrpcInterceptor {

        private final ServerInterceptor interceptor;
        private final int order;

        SecurityOrderedGrpcInterceptor(ServerInterceptor interceptor, int order) {
            this.interceptor = interceptor;
            this.order = order;
        }

        @Override
        public int order() {
            return order;
        }

        @Override
        public ServerInterceptor getInterceptor() {
            return interceptor;
        }
    }
}
