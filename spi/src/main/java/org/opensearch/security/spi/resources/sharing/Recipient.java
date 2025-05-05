/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.sharing;

/**
 * Enum representing the recipients of a shared resource.
 * It includes USERS, ROLES, and BACKEND_ROLES.
 *
 * @opensearch.experimental
 */
public enum Recipient {
    USERS("users"),
    ROLES("roles"),
    BACKEND_ROLES("backend_roles");

    private final String name;

    Recipient(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static Recipient fromValue(String name) {
        for (Recipient recipient : Recipient.values()) {
            if (recipient.name.equals(name)) {
                return recipient;
            }
        }
        throw new IllegalArgumentException("No Recipient with value: " + name);
    }

    @Override
    public String toString() {
        return name;
    }
}
