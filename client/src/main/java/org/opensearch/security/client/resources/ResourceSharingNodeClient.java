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
import org.opensearch.security.common.resources.ResourceSharing;
import org.opensearch.security.common.resources.rest.ResourceAccessAction;
import org.opensearch.security.common.resources.rest.ResourceAccessRequest;
import org.opensearch.security.common.resources.rest.ResourceAccessResponse;
import org.opensearch.security.spi.resources.Resource;
import org.opensearch.transport.client.Client;

public final class ResourceSharingNodeClient implements ResourceSharingClient {

    private final Client client;

    public ResourceSharingNodeClient(Client client) {
        this.client = client;
    }

    public void verifyResourceAccess(String resourceId, String resourceIndex, String scope, ActionListener<Boolean> listener) {
        ResourceAccessRequest request = new ResourceAccessRequest.Builder().operation(ResourceAccessRequest.Operation.VERIFY)
            .resourceId(resourceId)
            .resourceIndex(resourceIndex)
            .scope(scope)
            .build();
        client.execute(ResourceAccessAction.INSTANCE, request, verifyAccessResponseListener(listener));
    }

    public void shareResource(
        String resourceId,
        String resourceIndex,
        Map<String, Object> shareWith,
        ActionListener<ResourceSharing> listener
    ) {
        ResourceAccessRequest request = new ResourceAccessRequest.Builder().operation(ResourceAccessRequest.Operation.SHARE)
            .resourceId(resourceId)
            .resourceIndex(resourceIndex)
            .shareWith(shareWith)
            .build();
        client.execute(ResourceAccessAction.INSTANCE, request, sharingInfoResponseListener(listener));
    }

    public void revokeResourceAccess(
        String resourceId,
        String resourceIndex,
        Map<String, Object> entitiesToRevoke,
        Set<String> scopes,
        ActionListener<ResourceSharing> listener
    ) {
        ResourceAccessRequest request = new ResourceAccessRequest.Builder().operation(ResourceAccessRequest.Operation.REVOKE)
            .resourceId(resourceId)
            .resourceIndex(resourceIndex)
            .revokedEntities(entitiesToRevoke)
            .scopes(scopes)
            .build();
        client.execute(ResourceAccessAction.INSTANCE, request, sharingInfoResponseListener(listener));
    }

    public void listAccessibleResourcesForCurrentUser(String resourceIndex, ActionListener<Set<? extends Resource>> listener) {
        ResourceAccessRequest request = new ResourceAccessRequest.Builder().operation(ResourceAccessRequest.Operation.LIST)
            .resourceIndex(resourceIndex)
            .build();
        client.execute(ResourceAccessAction.INSTANCE, request, listResourcesResponseListener(listener));
    }

    private ActionListener<ResourceAccessResponse> verifyAccessResponseListener(ActionListener<Boolean> listener) {
        return ActionListener.wrap(response -> listener.onResponse(response.getHasPermission()), listener::onFailure);
    }

    private ActionListener<ResourceAccessResponse> sharingInfoResponseListener(ActionListener<ResourceSharing> listener) {
        return ActionListener.wrap(response -> listener.onResponse(response.getResourceSharing()), listener::onFailure);
    }

    private ActionListener<ResourceAccessResponse> listResourcesResponseListener(ActionListener<Set<? extends Resource>> listener) {
        return ActionListener.wrap(response -> listener.onResponse(response.getResources()), listener::onFailure);
    }
}
