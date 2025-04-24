/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.client;

import java.util.Set;

import org.opensearch.core.action.ActionListener;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;

/**
 * Interface for resource sharing client operations.
 *
 * @opensearch.experimental
 */
public interface ResourceSharingClient {

    /**
     * Verifies if the current user has access to the specified resource.
     * @param resourceId     The ID of the resource to verify access for.
     * @param resourceIndex  The index containing the resource.
     * @param listener       The listener to be notified with the access verification result.
     */
    void verifyResourceAccess(String resourceId, String resourceIndex, ActionListener<Boolean> listener);

    /**
     * Shares a resource with the specified users, roles, and backend roles.
     * @param resourceId     The ID of the resource to share.
     * @param resourceIndex  The index containing the resource.
     * @param recipients     The users, roles, and backend roles to share the resource with.
     * @param listener       The listener to be notified with the updated ResourceSharing document.
     */
    void share(
        String resourceId,
        String resourceIndex,
        SharedWithActionGroup.ActionGroupRecipients recipients,
        ActionListener<ResourceSharing> listener
    );

    /**
     * Revokes access to a resource for the specified entities.
     * @param resourceId     The ID of the resource to revoke access for.
     * @param resourceIndex  The index containing the resource.
     * @param entitiesToRevoke The entities to revoke access for.
     * @param listener       The listener to be notified with the updated ResourceSharing document.
     */
    void revoke(
        String resourceId,
        String resourceIndex,
        SharedWithActionGroup.ActionGroupRecipients entitiesToRevoke,
        ActionListener<ResourceSharing> listener
    );

    /**
     * Lists resourceIds of all shareable resources accessible by the current user.
     * @param resourceIndex The index containing the resources.
     * @param listener The listener to be notified with the set of accessible resources.
     */
    void getAccessibleResourceIds(String resourceIndex, ActionListener<Set<String>> listener);
}
