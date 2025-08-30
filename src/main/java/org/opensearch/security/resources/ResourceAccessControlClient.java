/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

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

    private final ResourceAccessHandler resourceAccessHandler;

    /**
     * Constructs a new ResourceAccessControlClient.
     *
     */
    public ResourceAccessControlClient(ResourceAccessHandler resourceAccessHandler) {
        this.resourceAccessHandler = resourceAccessHandler;
    }

    /**
     * Verifies whether the current user has access to the specified resource.
     *
     * @param resourceId    The ID of the resource to verify.
     * @param resourceIndex The index in which the resource resides.
     * @param listener      Callback that receives {@code true} if access is granted, {@code false} otherwise.
     */
    @Override
    public void verifyAccess(String resourceId, String resourceIndex, String action, ActionListener<Boolean> listener) {
        resourceAccessHandler.hasPermission(resourceId, resourceIndex, action, null, listener);
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
        resourceAccessHandler.revoke(resourceId, resourceIndex, target, listener);
    }
}
