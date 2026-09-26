/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth;

/**
 * Thrown by BackendRegistry.authcz() when the BCrypt concurrency
 * limiter (semaphore) rejects an authentication attempt due to saturation.
 *
 * <p>Callers MUST differentiate this from authentication failure so that:
 * <ul>
 *   <li>The caller responds with 503 SERVICE_UNAVAILABLE rather than 401.</li>
 *   <li>The IP-based rate limiter is NOT incremented -- throttling is not a
 *       credential failure and must not lock out legitimate clients during
 *       load spikes.</li>
 * </ul>
 */
public class AuthBackendThrottledException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AuthBackendThrottledException(String message) {
        super(message);
    }

    /**
     * Flow-control exception thrown under high load for semaphore-saturation
     * signaling. The throw site is always the same (BackendRegistry.authcz()),
     * so the stack trace adds no diagnostic value while adding measurable
     * CPU/GC cost when the system is already under stress. Suppress it.
     *
     * Same pattern as Netty's StacklessClosedChannelException.
     */
    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
