/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

/**
 * This class provides information about resource plugins and their associated resource providers and indices.
 * It follows the Singleton pattern to ensure that only one instance of the class exists.
 *
 * @opensearch.experimental
 */
public class ResourcePluginInfo {
    private static ResourcePluginInfo INSTANCE;

    private final Map<String, ResourceProvider> resourceProviderMap = new HashMap<>();
    private final Set<String> resourceIndices = new HashSet<>();

    public void setResourceProviders(Map<String, ResourceProvider> providerMap) {
        resourceProviderMap.clear();
        resourceProviderMap.putAll(providerMap);
    }

    public void setResourceIndices(Set<String> indices) {
        resourceIndices.clear();
        resourceIndices.addAll(indices);
    }

    public Map<String, ResourceProvider> getResourceProviders() {
        return ImmutableMap.copyOf(resourceProviderMap);
    }

    public Set<String> getResourceIndices() {
        return ImmutableSet.copyOf(resourceIndices);
    }

    // TODO following should be removed once core test framework allows loading extended classes
    public Map<String, ResourceProvider> getResourceProvidersMutable() {
        return resourceProviderMap;
    }

    public Set<String> getResourceIndicesMutable() {
        return resourceIndices;
    }
}
