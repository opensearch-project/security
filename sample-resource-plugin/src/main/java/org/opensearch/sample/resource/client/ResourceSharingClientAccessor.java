/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.client;

import org.opensearch.Version;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.client.resources.ResourceSharingNodeClient;
import org.opensearch.transport.client.node.NodeClient;

/**
 * Accessor for resource sharing node client.
 */
public class ResourceSharingClientAccessor {
    private static ResourceSharingNodeClient INSTANCE;

    private ResourceSharingClientAccessor() {}

    /**
     * Get resource sharing client
     *
     * @param nodeClient    node client
     * @param settings      settings
     * @param version       version
     * @return resource sharing client
     */
    public static ResourceSharingNodeClient getResourceSharingClient(NodeClient nodeClient, Settings settings, Version version) {
        if (INSTANCE == null) {
            INSTANCE = new ResourceSharingNodeClient(nodeClient, settings, version);
        }
        return INSTANCE;
    }
}
