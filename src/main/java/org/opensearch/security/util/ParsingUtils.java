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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ParsingUtils {

    /**
     * Safely casts an Object to List<String> with validation
     */
    public static List<String> safeStringList(Object obj, String fieldName) {
        if (obj == null) {
            return Collections.emptyList();
        }
        if (!(obj instanceof List<?> list)) {
            throw new IllegalArgumentException(fieldName + " must be an array");
        }

        for (Object item : list) {
            if (!(item instanceof String)) {
                throw new IllegalArgumentException(fieldName + " must contain only strings");
            }
        }

        return list.stream().map(String.class::cast).collect(Collectors.toList());
    }

    /**
     * Safely casts an Object to List<Map<String, Object>> with validation
     */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> safeMapList(Object obj, String fieldName) {
        if (obj == null) {
            return Collections.emptyList();
        }
        if (!(obj instanceof List<?> list)) {
            throw new IllegalArgumentException(fieldName + " must be an array");
        }

        for (Object item : list) {
            if (!(item instanceof Map)) {
                throw new IllegalArgumentException(fieldName + " must contain object entries");
            }
        }
        return list.stream().map(item -> (Map<String, Object>) item).collect(Collectors.toList());
    }
}
