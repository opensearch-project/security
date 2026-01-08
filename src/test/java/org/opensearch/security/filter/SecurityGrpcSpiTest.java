/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.security.filter;

import org.junit.Test;
import org.opensearch.transport.grpc.spi.GrpcInterceptorProvider;

import java.util.ServiceLoader;

import static org.junit.Assert.*;

public class SecurityGrpcSpiTest {

    @Test
    public void testSpiRegistration() {
        ServiceLoader<GrpcInterceptorProvider> loader = ServiceLoader.load(GrpcInterceptorProvider.class);
        
        boolean found = false;
        for (GrpcInterceptorProvider provider : loader) {
            if (provider instanceof SecurityGrpcFilter) {
                found = true;
                System.out.println("✓ Found SecurityGrpcFilter via SPI: " + provider.getClass().getName());
                break;
            }
        }
        
        assertTrue("SecurityGrpcFilter should be discoverable via SPI", found);
    }
}
