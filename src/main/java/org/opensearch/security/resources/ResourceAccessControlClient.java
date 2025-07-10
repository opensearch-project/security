/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;

/**
 * Access control client responsible for handling resource sharing operations such as verifying,
 * sharing, revoking, and listing access to shareable resources.
 *
 * @opensearch.experimental
 */
public final class ResourceAccessControlClient implements ResourceSharingClient {

    private static final Logger log = LogManager.getLogger(ResourceAccessControlClient.class);

    private final ResourceAccessHandler resourceAccessHandler;

    /**
     * Constructs a new ResourceAccessControlClient.
     *
     */
    public ResourceAccessControlClient(ResourceAccessHandler resourceAccessHandler, Settings settings) {
        this.resourceAccessHandler = resourceAccessHandler;
    }

    /**
     * Shares a resource with specified users, roles, or backend roles.
     *
     * @param resourceId    The ID of the resource to share.
     * @param resourceIndex The index containing the resource.
     * @param target        The recipients of the resource, including users, roles, and backend roles and respective access levels.
     * @param listener      Callback receiving the updated {@link ResourceSharing} document.
     */
    @Override
    public void share(String resourceId, String resourceIndex, ShareWith target, ActionListener<ResourceSharing> listener) {
        resourceAccessHandler.share(resourceId, resourceIndex, target, listener);
    }

    /**
     * Revokes previously granted access to a resource for specific users or roles.
     *
     * @param resourceId        The ID of the resource.
     * @param resourceIndex     The index containing the resource.
     * @param target            A map of entities whose access is to be revoked.
     * @param listener          Callback receiving the updated {@link ResourceSharing} document.
     */
    @Override
    public void revoke(String resourceId, String resourceIndex, ShareWith target, ActionListener<ResourceSharing> listener) {
        // TODO access level may be unnecessary in this API if a specific user or role can only be provisioned at a single access level
        resourceAccessHandler.revoke(resourceId, resourceIndex, target, listener);
    }

    /**
     * Lists all resources the current user has access to within the given index.
     *
     * @param resourceIndex The index to search for accessible resources.
     * @param listener      Callback receiving a set of resource ids.
     */
    @Override
    public void getAccessibleResourceIds(String resourceIndex, ActionListener<Set<String>> listener) {
        resourceAccessHandler.getOwnAndSharedResourceIdsForCurrentUser(resourceIndex, listener);
    }
}
