/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.util.Set;

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
     * @param resourceType  The resource tupe.
     * @param action        The action to be evaluated against
     * @param listener      Callback that receives {@code true} if access is granted, {@code false} otherwise.
     */
    @Override
    public void verifyAccess(String resourceId, String resourceType, String action, ActionListener<Boolean> listener) {
        resourceAccessHandler.hasPermission(resourceId, resourceType, action, null, listener);
    }

    /**
     * Shares a resource with specified users, roles, or backend roles.
     *
     * @param resourceId    The ID of the resource to share.
     * @param resourceType  The resource type.
     * @param target        The recipients of the resource, including users, roles, and backend roles and respective access levels.
     * @param listener      Callback receiving the updated {@link ResourceSharing} document.
     */
    @Override
    public void share(String resourceId, String resourceType, ShareWith target, ActionListener<ResourceSharing> listener) {
        resourceAccessHandler.share(resourceId, resourceType, target, listener);
    }

    /**
     * Revokes previously granted access to a resource for specific users or roles.
     *
     * @param resourceId        The ID of the resource.
     * @param resourceType      The resource type.
     * @param target            A map of entities whose access is to be revoked.
     * @param listener          Callback receiving the updated {@link ResourceSharing} document.
     */
    @Override
    public void revoke(String resourceId, String resourceType, ShareWith target, ActionListener<ResourceSharing> listener) {
        resourceAccessHandler.revoke(resourceId, resourceType, target, listener);
    }

    /**
     * Lists all resources the current user has access to within the given index.
     *
     * @param resourceType  The resource type.
     * @param listener      Callback receiving a set of resource ids.
     */
    @Override
    public void getAccessibleResourceIds(String resourceType, ActionListener<Set<String>> listener) {
        resourceAccessHandler.getOwnAndSharedResourceIdsForCurrentUser(resourceType, listener);
    }
}
