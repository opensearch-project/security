/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.security.grpc;

import java.util.ServiceLoader;

import org.junit.Test;

import org.opensearch.transport.grpc.spi.GrpcInterceptorProvider;
import org.opensearch.security.filter.SecurityGrpcFilter;

import static org.junit.Assert.assertTrue;

public class SecurityGrpcSpiIntegrationTest {

    @Test
    public void testSecurityGrpcFilterSpiRegistration() {
        // Test that SecurityGrpcFilter can be discovered via SPI
        ServiceLoader<GrpcInterceptorProvider> loader = ServiceLoader.load(
            GrpcInterceptorProvider.class, 
            SecurityGrpcFilter.class.getClassLoader()
        );
        
        boolean found = false;
        for (GrpcInterceptorProvider provider : loader) {
            System.out.println("Found GrpcInterceptorProvider: " + provider.getClass().getName());
            if (provider instanceof SecurityGrpcFilter) {
                found = true;
                System.out.println("✓ SecurityGrpcFilter found via SPI in integration test");
                break;
            }
        }
        
        assertTrue("SecurityGrpcFilter should be discoverable via SPI", found);
    }
}
