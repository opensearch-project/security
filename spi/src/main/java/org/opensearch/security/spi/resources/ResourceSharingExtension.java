/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import org.opensearch.security.spi.resources.client.ResourceSharingClient;

/**
 * This interface should be implemented by all the plugins that define one or more resources and need access control over those resources.
 *
 * @opensearch.experimental
 */
public interface ResourceSharingExtension {

    /**
     * Type of the resource
     * @return a string containing the type of the resource. A qualified class name can be supplied here.
     */
    String getResourceType();

    /**
     * The index where resource is stored
     * @return the name of the parent index where resource is stored
     */
    String getResourceIndex();

    /**
     * The parser for the resource, which will be used by security plugin to parse the resource
     * @return the parser for the resource
     */
    ShareableResourceParser<? extends ShareableResource> getShareableResourceParser();

    /**
     * Assigns the ResourceSharingClient to the resource plugin. Plugins can then utilize this to call the methods for access control.
     * @param client the ResourceSharingClient instance
     */
    void assignResourceSharingClient(ResourceSharingClient client);

}
