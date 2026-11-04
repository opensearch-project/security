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

package org.opensearch.security.hasher;

/**
 * Test double for {@code org.bouncycastle.crypto.fips.FipsUnapprovedOperationError}.
 * Extends {@link Error} (not {@link Exception}) so it mirrors Bouncy Castle FIPS
 * provider behavior without requiring the FIPS JAR on the unit-test classpath.
 * Detection keys off the simple class name {@code FipsUnapprovedOperationError}.
 */
public class FipsUnapprovedOperationError extends Error {

    public FipsUnapprovedOperationError() {
        super();
    }

    public FipsUnapprovedOperationError(String message) {
        super(message);
    }

    public FipsUnapprovedOperationError(String message, Throwable cause) {
        super(message, cause);
    }
}
