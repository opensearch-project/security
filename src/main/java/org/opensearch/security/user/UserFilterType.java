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

/**
 *  Filter types to be used when requesting the list of users.
 *  'Service' refers to accounts used by other services like Dashboards
 *  'Internal' refers the standard user accounts
 *  'Any' refers to both types of accounts
 */
public enum UserFilterType {

    ANY("any"),
    INTERNAL("internal"),
    SERVICE("service");

    private String name;

    UserFilterType(String name) {
        this.name = name;
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
