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

import org.opensearch.OpenSearchSecurityException;

/**
 * Helpers for detecting and converting Bouncy Castle FIPS policy Errors
 * (notably {@code FipsUnapprovedOperationError}) that extend {@link Error}
 * rather than {@link Exception}, and therefore bypass ordinary catch blocks.
 */
public final class FipsErrors {

    public static final String FIPS_UNAPPROVED_OPERATION_ERROR = "org.bouncycastle.crypto.fips.FipsUnapprovedOperationError";

    private static final String FIPS_UNAPPROVED_OPERATION_SIMPLE_NAME = "FipsUnapprovedOperationError";

    private FipsErrors() {}

    /**
     * Walks the cause chain and returns true if any throwable is a FIPS
     * unapproved-operation Error. Matches the Bouncy Castle FQCN and also the
     * simple class name so shaded jars and unit-test doubles are recognized.
     */
    public static boolean isFipsUnapprovedOperationError(Throwable throwable) {
        for (Throwable t = throwable; t != null; t = t.getCause()) {
            if (isFipsUnapprovedOperationErrorClassName(t.getClass().getName())
                || FIPS_UNAPPROVED_OPERATION_SIMPLE_NAME.equals(t.getClass().getSimpleName())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Package-visible for unit tests. Matches the Bouncy Castle FQCN, a bare
     * simple name, or any class name ending in {@code .FipsUnapprovedOperationError}
     * (shaded packages).
     */
    static boolean isFipsUnapprovedOperationErrorClassName(String className) {
        if (className == null || className.isEmpty()) {
            return false;
        }
        return FIPS_UNAPPROVED_OPERATION_ERROR.equals(className)
            || FIPS_UNAPPROVED_OPERATION_SIMPLE_NAME.equals(className)
            || className.endsWith("." + FIPS_UNAPPROVED_OPERATION_SIMPLE_NAME);
    }

    /**
     * Converts a FIPS unapproved-operation {@link Error} into an
     * {@link OpenSearchSecurityException}; otherwise rethrows the Error so
     * fatal JVM conditions (OOM, StackOverflow, etc.) are not swallowed.
     */
    public static OpenSearchSecurityException asSecurityExceptionOrPropagate(Error e) {
        if (isFipsUnapprovedOperationError(e)) {
            return new OpenSearchSecurityException("password rejected by FIPS policy", e);
        }
        throw e;
    }
}
