/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.sharing;

/**
 * This enum is used to store information about the creator of a resource.
 *
 * @opensearch.experimental
 */
public enum Creator {
    USER("user");

    private final String name;

    Creator(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static Creator fromName(String name) {
        for (Creator creator : values()) {
            if (creator.name.equalsIgnoreCase(name)) { // Case-insensitive comparison
                return creator;
            }
        }
        throw new IllegalArgumentException("No enum constant for name: " + name);
    }
}
