/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.support;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;

import org.opensearch.core.common.Strings;
import org.opensearch.security.DefaultObjectMapper;

public class JsonFlattener {

    public static Map<String, Object> flattenAsMap(String jsonString) {
        try {
            final TypeReference<Map<String, Object>> typeReference = new TypeReference<>() {
            };
            final Map<String, Object> jsonMap = DefaultObjectMapper.objectMapper.readValue(jsonString, typeReference);
            final Map<String, Object> flattenMap = new LinkedHashMap<>();
            flattenEntries("", jsonMap.entrySet(), flattenMap);
            return flattenMap;
        } catch (final IOException ioe) {
            throw new IllegalArgumentException("Unparseable json", ioe);
        }
    }

    private static void flattenEntries(String prefix, final Iterable<Map.Entry<String, Object>> entries, final Map<String, Object> result) {
        if (!Strings.isNullOrEmpty(prefix)) {
            prefix += ".";
        }

        for (final Map.Entry<String, Object> e : entries) {
            flattenElement(prefix.concat(e.getKey()), e.getValue(), result);
        }
    }

    @SuppressWarnings("unchecked")
    private static void flattenElement(String prefix, final Object source, final Map<String, Object> result) {
        if (source instanceof Iterable) {
            flattenCollection(prefix, (Iterable<Object>) source, result);
        }
        if (source instanceof Map) {
            flattenEntries(prefix, ((Map<String, Object>) source).entrySet(), result);
        }
        result.put(prefix, source);
    }

    private static void flattenCollection(String prefix, final Iterable<Object> objects, final Map<String, Object> result) {
        int counter = 0;
        for (final Object o : objects) {
            flattenElement(prefix + "[" + counter + "]", o, result);
            counter++;
        }
    }

}
