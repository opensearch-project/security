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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.common.resources.rest.ResourceAccessAction;
import org.opensearch.security.common.resources.rest.ResourceAccessRequest;
import org.opensearch.security.common.resources.rest.ResourceAccessResponse;
import org.opensearch.security.common.support.ConfigConstants;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.transport.client.Client;

/**
 * Client for resource sharing operations.
 *
 * @opensearch.experimental
 */
public final class ResourceSharingNodeClient implements ResourceSharingClient {

    private static final Logger log = LogManager.getLogger(ResourceSharingNodeClient.class);

    private final Client client;
    private final boolean resourceSharingEnabled;

    public ResourceSharingNodeClient(Client client, Settings settings) {
        this.client = client;
        this.resourceSharingEnabled = settings.getAsBoolean(
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED,
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT
        );
    }

    /**
     * Verifies if the current user has access to the specified resource.
     * @param resourceId     The ID of the resource to verify access for.
     * @param resourceIndex  The index containing the resource.
     * @param scopes         The scopes to be checked against.
     * @param listener       The listener to be notified with the access verification result.
     */
    @Override
    public void verifyResourceAccess(String resourceId, String resourceIndex, Set<String> scopes, ActionListener<Boolean> listener) {
        if (!resourceSharingEnabled) {
            log.warn("Resource Access Control feature is disabled. Access to resource is automatically granted.");
            listener.onResponse(true);
            return;
        }
        ResourceAccessRequest request = new ResourceAccessRequest.Builder().operation(ResourceAccessRequest.Operation.VERIFY)
            .resourceId(resourceId)
            .resourceIndex(resourceIndex)
            .scopes(scopes)
            .build();
        client.execute(ResourceAccessAction.INSTANCE, request, verifyAccessResponseListener(listener));
    }

    /**
     * Shares the specified resource with the given users, roles, and backend roles.
     * @param resourceId     The ID of the resource to share.
     * @param resourceIndex  The index containing the resource.
     * @param shareWith      The users, roles, and backend roles to share the resource with.
     * @param listener       The listener to be notified with the updated ResourceSharing document.
     */
    @Override
    public void shareResource(
        String resourceId,
        String resourceIndex,
        Map<String, Object> shareWith,
        ActionListener<ResourceSharing> listener
    ) {
        if (isResourceAccessControlDisabled("Resource is not shareable.", listener)) {
            return;
        }
        ResourceAccessRequest request = new ResourceAccessRequest.Builder().operation(ResourceAccessRequest.Operation.SHARE)
            .resourceId(resourceId)
            .resourceIndex(resourceIndex)
            .shareWith(shareWith)
            .build();
        client.execute(ResourceAccessAction.INSTANCE, request, sharingInfoResponseListener(listener));
    }

    /**
     * Revokes access to the specified resource for the given entities and scopes.
     * @param resourceId     The ID of the resource to revoke access for.
     * @param resourceIndex  The index containing the resource.
     * @param entitiesToRevoke The entities to revoke access for.
     * @param scopes         The scopes to revoke access for.
     * @param listener       The listener to be notified with the updated ResourceSharing document.
     */
    @Override
    public void revokeResourceAccess(
        String resourceId,
        String resourceIndex,
        Map<String, Object> entitiesToRevoke,
        Set<String> scopes,
        ActionListener<ResourceSharing> listener
    ) {
        if (isResourceAccessControlDisabled("Resource access is not revoked.", listener)) {
            return;
        }
        ResourceAccessRequest request = new ResourceAccessRequest.Builder().operation(ResourceAccessRequest.Operation.REVOKE)
            .resourceId(resourceId)
            .resourceIndex(resourceIndex)
            .revokedEntities(entitiesToRevoke)
            .scopes(scopes)
            .build();
        client.execute(ResourceAccessAction.INSTANCE, request, sharingInfoResponseListener(listener));
    }

    /**
     * Helper method for share/revoke to check and return early is resource sharing is disabled
     * @param disabledMessage The message to be logged if resource sharing is disabled.
     * @param listener        The listener to be notified with the error.
     * @return true if resource sharing is enabled, false otherwise.
     */
    private boolean isResourceAccessControlDisabled(String disabledMessage, ActionListener<?> listener) {
        if (!resourceSharingEnabled) {
            log.warn("Resource Access Control feature is disabled. {}", disabledMessage);

            listener.onFailure(
                new OpenSearchException("Resource Access Control feature is disabled. " + disabledMessage, RestStatus.NOT_IMPLEMENTED)
            );
            return true;
        }
        return false;
    }

    /**
     * Notifies the listener with the access request result.
     * @param listener The listener to be notified with the access request result.
     * @return An ActionListener that handles the ResourceAccessResponse and notifies the listener.
     */
    private ActionListener<ResourceAccessResponse> verifyAccessResponseListener(ActionListener<Boolean> listener) {
        return ActionListener.wrap(response -> listener.onResponse(response.getHasPermission()), listener::onFailure);
    }

    /**
     * Notifies the listener with the updated ResourceSharing document.
     * @param listener The listener to be notified with the updated ResourceSharing document.
     * @return An ActionListener that handles the ResourceAccessResponse and notifies the listener.
     */
    private ActionListener<ResourceAccessResponse> sharingInfoResponseListener(ActionListener<ResourceSharing> listener) {
        return ActionListener.wrap(response -> listener.onResponse(response.getResourceSharing()), listener::onFailure);
    }
}
