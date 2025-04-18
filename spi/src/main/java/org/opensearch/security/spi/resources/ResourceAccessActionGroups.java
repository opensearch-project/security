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
 * This class represents action-groups to be utilized to share resources.
 *
 * @opensearch.experimental
 */
public interface ResourceAccessActionGroups<T extends Enum<T>> {
    // TODO update following comment once ResourceAuthz is implemented as a standalone framework
    // At present, we define this place-holder value represents the default action group this resource is shared with.
    String PLACE_HOLDER = "default";

    static <E extends Enum<E> & ResourceAccessActionGroups<E>> E fromValue(Class<E> enumClass, String value) {
        for (E enumConstant : enumClass.getEnumConstants()) {
            if (enumConstant.value().equalsIgnoreCase(value)) {
                return enumConstant;
            }
        }
        throw new IllegalArgumentException("Unknown value: " + value);
    }

    String value();

    static <E extends Enum<E> & ResourceAccessActionGroups<E>> String[] values(Class<E> enumClass) {
        return Arrays.stream(enumClass.getEnumConstants()).map(ResourceAccessActionGroups::value).toArray(String[]::new);
    }
}
