/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.util.Arrays;

/**
 * This interface defines the two basic access scopes for resource-access. Plugins can decide whether to use these.
 * Each plugin must implement their own scopes and manage them.
 * These access scopes will then be used to verify the type of access being requested.
 *
 * @opensearch.experimental
 */
public interface ResourceAccessScope<T extends Enum<T>> {
    String READ_ONLY = "read_only";
    String PUBLIC = "public"; // users: ["*"], roles: ["*"], backend_roles: ["*"]

    static <E extends Enum<E> & ResourceAccessScope<E>> E fromValue(Class<E> enumClass, String value) {
        for (E enumConstant : enumClass.getEnumConstants()) {
            if (enumConstant.value().equalsIgnoreCase(value)) {
                return enumConstant;
            }
        }
        throw new IllegalArgumentException("Unknown value: " + value);
    }

    String value();

    static <E extends Enum<E> & ResourceAccessScope<E>> String[] values(Class<E> enumClass) {
        return Arrays.stream(enumClass.getEnumConstants()).map(ResourceAccessScope::value).toArray(String[]::new);
    }
}
