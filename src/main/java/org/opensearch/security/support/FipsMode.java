/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.support;

/**
 * Single source of truth for FIPS mode detection.
 * Set {@code OPENSEARCH_FIPS_MODE=true} in the environment to enable.
 */
public final class FipsMode {

    static java.util.function.Supplier<String> envSupplier = () -> System.getenv("OPENSEARCH_FIPS_MODE");

    public static boolean isEnabled() {
        return "true".equalsIgnoreCase(envSupplier.get());
    }

    private FipsMode() {
        throw new UnsupportedOperationException();
    }
}
