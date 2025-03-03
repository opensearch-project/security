/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.client;

import org.opensearch.security.client.resources.ResourceSharingNodeClient;
import org.opensearch.transport.client.node.NodeClient;

public class ResourceSharingClientAccessor {
    private static ResourceSharingNodeClient INSTANCE;

    private ResourceSharingClientAccessor() {}

    /**
     * get machine learning client.
     *
     * @param nodeClient node client
     * @return machine learning client
     */
    public static ResourceSharingNodeClient getResourceSharingClient(NodeClient nodeClient) {
        if (INSTANCE == null) {
            INSTANCE = new ResourceSharingNodeClient(nodeClient);
        }
        return INSTANCE;
    }
}
