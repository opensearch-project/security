/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.config;

import java.util.Arrays;

/**
 * A key store password, key password or PKCS#11 token PIN - a critical security parameter. Wrapping the
 * characters keeps them off the public surface of the store configurations: the array is unwrapped only
 * within this package, at the JCA calls that insist on a {@code char[]}. Equality is by content, and
 * {@link #toString()} never reveals the characters.
 */
public final class StorePassword {

    public static final StorePassword NONE = new StorePassword(null);

    private final char[] password;

    private StorePassword(final char[] password) {
        this.password = password;
    }

    public static StorePassword of(final char[] password) {
        return password != null ? new StorePassword(password) : NONE;
    }

    /**
     * @return the characters, or {@code null} for {@link #NONE}.
     */
    char[] chars() {
        return password;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final var other = ((StorePassword) o).password;
        if (password == null || other == null) {
            return password == other;
        }
        if (password.length != other.length) {
            return false;
        }
        var difference = 0;
        for (int i = 0; i < password.length; i++) {
            difference |= password[i] ^ other[i];
        }
        return difference == 0;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(password);
    }

    @Override
    public String toString() {
        return password != null ? "***" : "<none>";
    }
}
