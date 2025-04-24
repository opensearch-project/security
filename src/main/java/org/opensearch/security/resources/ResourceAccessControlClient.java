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
import org.opensearch.security.spi.resources.ResourceAccessActionGroups;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;

/**
 * Access control client responsible for handling resource sharing operations such as verifying,
 * sharing, revoking, and listing access to shareable resources.
 *
 * @opensearch.experimental
 */
public final class ResourceAccessControlClient implements ResourceSharingClient {

    private static final Logger log = LogManager.getLogger(ResourceAccessControlClient.class);

    private final ResourceAccessHandler resourceAccessHandler;
    private final Settings settings;

    /**
     * Constructs a new ResourceAccessControlClient.
     *
     */
    public ResourceAccessControlClient(ResourceAccessHandler resourceAccessHandler, Settings settings) {
        this.resourceAccessHandler = resourceAccessHandler;
        this.settings = settings;
    }

    /**
     * Verifies whether the current user has access to the specified resource.
     *
     * @param resourceId    The ID of the resource to verify.
     * @param resourceIndex The index in which the resource resides.
     * @param listener      Callback that receives {@code true} if access is granted, {@code false} otherwise.
     */
    @Override
    public void verifyResourceAccess(String resourceId, String resourceIndex, ActionListener<Boolean> listener) {
        resourceAccessHandler.hasPermission(resourceId, resourceIndex, Set.of(ResourceAccessActionGroups.PLACE_HOLDER), listener);
    }

    /**
     * Shares a resource with specified users, roles, or backend roles.
     *
     * @param resourceId    The ID of the resource to share.
     * @param resourceIndex The index containing the resource.
     * @param recipients    The recipients of the resource, including users, roles, and backend roles.
     * @param listener      Callback receiving the updated {@link ResourceSharing} document.
     */
    @Override
    public void share(
        String resourceId,
        String resourceIndex,
        SharedWithActionGroup.ActionGroupRecipients recipients,
        ActionListener<ResourceSharing> listener
    ) {
        SharedWithActionGroup sharedWithActionGroup = new SharedWithActionGroup(ResourceAccessActionGroups.PLACE_HOLDER, recipients);
        ShareWith shareWith = new ShareWith(Set.of(sharedWithActionGroup));

        resourceAccessHandler.shareWith(resourceId, resourceIndex, shareWith, listener);
    }

    /**
     * Revokes previously granted access to a resource for specific users or roles.
     *
     * @param resourceId        The ID of the resource.
     * @param resourceIndex     The index containing the resource.
     * @param entitiesToRevoke  A map of entities whose access is to be revoked.
     * @param listener          Callback receiving the updated {@link ResourceSharing} document.
     */
    @Override
    public void revoke(
        String resourceId,
        String resourceIndex,
        SharedWithActionGroup.ActionGroupRecipients entitiesToRevoke,
        ActionListener<ResourceSharing> listener
    ) {
        resourceAccessHandler.revokeAccess(
            resourceId,
            resourceIndex,
            entitiesToRevoke,
            Set.of(ResourceAccessActionGroups.PLACE_HOLDER),
            listener
        );
    }

    /**
     * Lists all resources the current user has access to within the given index.
     *
     * @param resourceIndex The index to search for accessible resources.
     * @param listener      Callback receiving a set of resource ids.
     */
    @Override
    public void getAccessibleResourceIds(String resourceIndex, ActionListener<Set<String>> listener) {
        resourceAccessHandler.getAccessibleResourceIdsForCurrentUser(resourceIndex, listener);
    }
}
