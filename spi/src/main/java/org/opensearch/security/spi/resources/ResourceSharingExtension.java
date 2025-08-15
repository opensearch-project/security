/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.util.Set;

import org.opensearch.security.spi.resources.client.ResourceSharingClient;

/**
 * This interface should be implemented by all the plugins that define one or more resources and need access control over those resources.
 *
 * @opensearch.experimental
 */
public interface ResourceSharingExtension {

    /**
     * Returns the set of {@link ResourceProvider} instances for the resources defined by the plugin.
     * Only in the case where plugin defines multiple resources, will there be more than one resource provider
    *
     * @return the set of ResourceProvider instances
     */
    Set<ResourceProvider> getResourceProviders();

    /**
     * Assigns the ResourceSharingClient to the resource plugin. Plugins can then utilize this to call the methods for access control.
     * @param client the ResourceSharingClient instance
     */
    void assignResourceSharingClient(ResourceSharingClient client);

    /**
     * Returns the assigned resource sharing client
     */
    ResourceSharingClient getResourceSharingClient();
}
