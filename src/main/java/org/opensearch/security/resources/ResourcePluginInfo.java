/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

// CS-SUPPRESS-SINGLE: RegexpSingleline get Resource Sharing Extensions
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;

import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;

/**
 * This class provides information about resource plugins and their associated resource providers and indices.
 * It follows the Singleton pattern to ensure that only one instance of the class exists.
 *
 * @opensearch.experimental
 */
public class ResourcePluginInfo {

    private final Set<ResourceSharingExtension> resourceSharingExtensions = new HashSet<>();

    public void setResourceSharingExtensions(Set<ResourceSharingExtension> extensions) {
        resourceSharingExtensions.addAll(extensions);
    }

    public Set<ResourceSharingExtension> getResourceSharingExtensions() {
        return ImmutableSet.copyOf(resourceSharingExtensions);
    }

    public Set<String> getResourceIndices() {
        return resourceSharingExtensions.stream()
            .flatMap(ext -> ext.getResourceProviders().stream().map(ResourceProvider::resourceIndexName))
            .collect(Collectors.toSet());
    }
}
// CS-ENFORCE-SINGLE
