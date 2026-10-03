/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class AuthBackendThrottledExceptionTest {

    @Test
    public void messageIsPreserved() {
        AuthBackendThrottledException ex = new AuthBackendThrottledException("BCrypt concurrency limit reached for user admin");
        assertEquals("BCrypt concurrency limit reached for user admin", ex.getMessage());
    }

    @Test
    public void isUncheckedRuntimeException() {
        // Must be a RuntimeException so the Guava cache Callable can throw it without
        // declaring throws (and so callers don't have to catch it forced).
        AuthBackendThrottledException ex = new AuthBackendThrottledException("x");
        assertTrue("must be RuntimeException", ex instanceof RuntimeException);
    }

    @Test
    public void stackTraceIsSuppressed() {
        // Critical perf optimization: under saturation we throw this from a single,
        // well-known site (BackendRegistry.authcz) so the stack trace adds zero
        // diagnostic value while costing CPU/GC. fillInStackTrace() returns `this`
        // -> the throwable retains an empty stack-trace array.
        AuthBackendThrottledException ex = new AuthBackendThrottledException("x");
        StackTraceElement[] trace = ex.getStackTrace();
        assertEquals("stack trace should be empty (suppressed)", 0, trace.length);
    }

    @Test
    public void fillInStackTraceReturnsThis() {
        // Direct contract test: same Throwable identity returned from fillInStackTrace
        // -- JVM optimization shortcut, identical pattern to Netty's
        // StacklessClosedChannelException.
        AuthBackendThrottledException ex = new AuthBackendThrottledException("x");
        Throwable t = ex.fillInStackTrace();
        assertSame("fillInStackTrace must return same instance", ex, t);
    }

    @Test
    public void notAnAuthSecurityException() {
        // Crucial for caller logic: AuthBackendThrottledException must NOT be a
        // subclass of OpenSearchSecurityException, otherwise BackendRegistry's
        // generic catch(Exception) for security failures would absorb it instead of
        // letting it propagate up to the 503 response handler.
        assertFalse(
            "must NOT inherit from OpenSearchSecurityException -- would be miscategorized as auth failure",
            org.opensearch.OpenSearchSecurityException.class.isAssignableFrom(AuthBackendThrottledException.class)
        );
    }
}
