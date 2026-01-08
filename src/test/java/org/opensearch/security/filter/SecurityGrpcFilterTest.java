/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.security.filter;

import org.junit.Test;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.settings.Settings;

import static org.junit.Assert.*;

public class SecurityGrpcFilterTest {

    @Test
    public void testInterceptorProviderRegistration() {
        SecurityGrpcFilter provider = new SecurityGrpcFilter();
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        
        var interceptors = provider.getOrderedGrpcInterceptors(threadContext);
        
        assertNotNull("Interceptors should not be null", interceptors);
        assertEquals("Should return exactly one interceptor", 1, interceptors.size());
        assertEquals("Order should be 0", 0, interceptors.get(0).order());
        assertNotNull("Interceptor should not be null", interceptors.get(0).getInterceptor());
        
        System.out.println("✓ SecurityGrpcFilter test passed - interceptor provider works");
    }
}
