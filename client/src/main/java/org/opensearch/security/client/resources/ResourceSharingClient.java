/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.client.resources;

import java.util.Map;
import java.util.Set;

import org.opensearch.core.action.ActionListener;
import org.opensearch.security.spi.resources.ShareableResource;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;

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
     * @param scopes         The scopes to be checked against.
     * @param listener       The listener to be notified with the access verification result.
     */
    void verifyResourceAccess(String resourceId, String resourceIndex, Set<String> scopes, ActionListener<Boolean> listener);

    /**
     * Shares a resource with the specified users, roles, and backend roles.
     * @param resourceId     The ID of the resource to share.
     * @param resourceIndex  The index containing the resource.
     * @param shareWith      The users, roles, and backend roles to share the resource with.
     * @param listener       The listener to be notified with the updated ResourceSharing document.
     */
    void shareResource(String resourceId, String resourceIndex, Map<String, Object> shareWith, ActionListener<ResourceSharing> listener);

    /**
     * Revokes access to a resource for the specified entities and scopes.
     * @param resourceId     The ID of the resource to revoke access for.
     * @param resourceIndex  The index containing the resource.
     * @param entitiesToRevoke The entities to revoke access for.
     * @param scopes         The scopes to revoke access for.
     * @param listener       The listener to be notified with the updated ResourceSharing document.
     */
    void revokeResourceAccess(
        String resourceId,
        String resourceIndex,
        Map<String, Object> entitiesToRevoke,
        Set<String> scopes,
        ActionListener<ResourceSharing> listener
    );

    /**
     * Lists all resources accessible by the current user.
     * @param resourceIndex The index containing the resources.
     * @param listener The listener to be notified with the set of accessible resources.
     */
    void listAllAccessibleResources(String resourceIndex, ActionListener<Set<? extends ShareableResource>> listener);
}
