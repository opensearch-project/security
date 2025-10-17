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

package org.opensearch.test.framework.data;

import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

public class TestMapping {

    private final ImmutableMap<String, ?> properties;

    public TestMapping(Property... properties) {
        this.properties = ImmutableMap.copyOf(
            ImmutableList.copyOf(properties).stream().collect(ImmutableMap.toImmutableMap(Property::getName, Property::getAsMap))
        );
    }

    public Map<String, ?> getAsMap() {
        return ImmutableMap.of("properties", this.properties);
    }

    public static class Property {
        final String name;
        final String type;
        final String format;

        public Property(String name, String type, String format) {
            this.name = name;
            this.type = type;
            this.format = format;
        }

        public String getName() {
            return name;
        }

        public Map<String, ?> getAsMap() {
            return ImmutableMap.of("type", type, "format", format);
        }
    }
}
