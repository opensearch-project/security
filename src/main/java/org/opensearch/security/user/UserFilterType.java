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

package org.opensearch.security.user;

public enum UserFilterType {

    ANY("any"),
    INTERNAL("internal"),
    SERVICE("service");

    private String name;

    UserFilterType(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public static UserFilterType fromString(String name) {
        for (UserFilterType b : UserFilterType.values()) {
            if (b.name.equalsIgnoreCase(name)) {
                return b;
            }
        }
        return UserFilterType.ANY;
    }

}
