/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.client;

import org.opensearch.security.spi.resources.NoopResourceSharingClient;
import org.opensearch.security.spi.resources.ResourceSharingClient;

/**
 * Accessor for resource sharing client supplied by the SPI.
 */
public class ResourceSharingClientAccessor {
    private static ResourceSharingClient CLIENT;

    private ResourceSharingClientAccessor() {}

    /**
     * Set the resource sharing client
     */
    public static void setResourceSharingClient(ResourceSharingClient client) {
        CLIENT = client;
    }

    /**
     * Get the resource sharing client
     */
    public static ResourceSharingClient getResourceSharingClient() {
        return CLIENT == null ? new NoopResourceSharingClient() : CLIENT;
    }
}
