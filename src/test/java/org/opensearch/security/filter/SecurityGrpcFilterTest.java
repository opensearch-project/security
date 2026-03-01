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

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.ssl.OpenSearchSecuritySSLPlugin;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.transport.grpc.spi.GrpcInterceptorProvider;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SecurityGrpcFilterTest {

    @Mock
    private BackendRegistry backendRegistry;

    @Mock
    private AuditLog auditLog;

    private SecurityGrpcFilter securityGrpcFilter;
    private ThreadContext threadContext;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        securityGrpcFilter = new SecurityGrpcFilter();
        threadContext = new ThreadContext(Settings.EMPTY);
    }

    @Test
    public void testSecurityDisabledReturnsEmptyList() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_DISABLED, true).build();

        securityGrpcFilter.initNodeSettings(settings);
        List<GrpcInterceptorProvider.OrderedGrpcInterceptor> interceptors = securityGrpcFilter.getOrderedGrpcInterceptors(threadContext);

        assertTrue(interceptors.isEmpty());
    }

    @Test
    public void testSslOnlyReturnsEmptyList() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_SSL_ONLY, true).build();

        securityGrpcFilter.initNodeSettings(settings);
        List<GrpcInterceptorProvider.OrderedGrpcInterceptor> interceptors = securityGrpcFilter.getOrderedGrpcInterceptors(threadContext);

        assertTrue(interceptors.isEmpty());
    }

    @Test
    public void testNonNodeClientTypeReturnsEmptyList() {
        Settings settings = Settings.builder().put(OpenSearchSecuritySSLPlugin.CLIENT_TYPE, "transport").build();

        securityGrpcFilter.initNodeSettings(settings);
        List<GrpcInterceptorProvider.OrderedGrpcInterceptor> interceptors = securityGrpcFilter.getOrderedGrpcInterceptors(threadContext);

        assertTrue(interceptors.isEmpty());
    }

    @Test
    public void testNormalConfigurationReturnsInterceptor() {
        Settings settings = Settings.builder().put(OpenSearchSecuritySSLPlugin.CLIENT_TYPE, "node").build();

        securityGrpcFilter.initNodeSettings(settings);

        try {
            List<GrpcInterceptorProvider.OrderedGrpcInterceptor> interceptors = securityGrpcFilter.getOrderedGrpcInterceptors(
                threadContext
            );
            assertEquals(1, interceptors.size());
            interceptors.get(0).getInterceptor(); // This will throw due to uninitialized GuiceHolder
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("GuiceHolder") || e instanceof NullPointerException);
        }
    }

    @Test
    public void testInterceptorOrderIsMinValue() {
        Settings settings = Settings.builder().put(OpenSearchSecuritySSLPlugin.CLIENT_TYPE, "node").build();

        securityGrpcFilter.initNodeSettings(settings);

        List<GrpcInterceptorProvider.OrderedGrpcInterceptor> interceptors = securityGrpcFilter.getOrderedGrpcInterceptors(threadContext);

        assertEquals("Should return exactly one interceptor", 1, interceptors.size());
        assertEquals(
            "Security interceptor should have highest priority (Integer.MIN_VALUE)",
            Integer.MIN_VALUE,
            interceptors.get(0).order()
        );
    }
}
