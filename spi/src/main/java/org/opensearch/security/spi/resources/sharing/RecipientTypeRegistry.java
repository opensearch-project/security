/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.sharing;

import java.util.HashMap;
import java.util.Map;

/**
 * This class determines a collection of recipient types a resource can be shared with.
 * Allows addition of other recipient types in the future.
 *
 * @opensearch.experimental
 */
public final class RecipientTypeRegistry {
    // TODO: Check what size should this be. A cap should be added to avoid infinite addition of objects
    private static final Integer REGISTRY_MAX_SIZE = 20;
    private static final Map<String, RecipientType> REGISTRY = new HashMap<>(10);

    public static void registerRecipientType(String key, RecipientType recipientType) {
        if (REGISTRY.size() == REGISTRY_MAX_SIZE) {
            throw new IllegalArgumentException("RecipientTypeRegistry is full. Cannot register more recipient types.");
        }
        REGISTRY.put(key, recipientType);
    }

    public static RecipientType fromValue(String value) {
        RecipientType type = REGISTRY.get(value);
        if (type == null) {
            throw new IllegalArgumentException("Unknown RecipientType: " + value + ". Must be 1 of these: " + REGISTRY.values());
        }
        return type;
    }
}
