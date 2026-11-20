/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth;

import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class InvalidCredentialsExceptionTest {

    @Test
    public void messageIsPreserved() {
        InvalidCredentialsException ex = new InvalidCredentialsException("user xyz not found");
        assertEquals("user xyz not found", ex.getMessage());
    }

    @Test
    public void isSecurityException() {
        // BackendRegistry catches the security exception broadly; the typed subclass
        // must remain assignable so existing callers keep working without changes.
        InvalidCredentialsException ex = new InvalidCredentialsException("password does not match");
        assertTrue("must extend OpenSearchSecurityException", ex instanceof OpenSearchSecurityException);
    }

    @Test
    public void canCarryStackTrace() {
        // Unlike AuthBackendThrottledException, this is a real auth failure and SHOULD
        // capture a stack trace for diagnostics.
        InvalidCredentialsException ex = new InvalidCredentialsException("bad");
        StackTraceElement[] trace = ex.getStackTrace();
        assertNotNull(trace);
        assertTrue("stack trace should be populated", trace.length > 0);
    }
}
