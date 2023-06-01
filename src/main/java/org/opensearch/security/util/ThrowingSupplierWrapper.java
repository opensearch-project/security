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

package org.opensearch.security.util;

import java.util.function.Supplier;

public class ThrowingSupplierWrapper {
    /*
     * Private constructor to avoid Jacoco complaining about public constructor
     * not covered: https://tinyurl.com/yetc7tra
     */
    private ThrowingSupplierWrapper() {}

    /**
     * Utility method to use a method throwing checked exception inside a place
     *  that does not allow throwing the corresponding checked exception (e.g.,
     *  enum initialization).
     * Convert the checked exception thrown by by throwingConsumer to a RuntimeException
     * so that the compiler won't complain.
     * @param <T> the method's return type
     * @param throwingSupplier the method reference that can throw checked exception
     * @return converted method reference
     */
    public static <T> Supplier<T> throwingSupplierWrapper(ThrowingSupplier<T, Exception> throwingSupplier) {

        return () -> {
            try {
                return throwingSupplier.get();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        };
    }
}
