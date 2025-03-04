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

    public void verifyResourceAccess(String resourceId, String resourceIndex, String scope, ActionListener<Boolean> listener) {
        if (!resourceSharingEnabled) {
            log.warn("Resource Access Control feature is disabled. Access to resource is automatically granted.");
            listener.onResponse(true);
            return;
        }
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
        if (!resourceSharingEnabled) {
            log.warn("Resource Access Control feature is disabled. Resource is not shareable.");
            listener.onFailure(
                new OpenSearchException(
                    "Resource Access Control feature is disabled. Resource is not shareable.",
                    RestStatus.NOT_IMPLEMENTED
                )
            );
            return;
        }
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
        if (!resourceSharingEnabled) {
            log.warn("Resource Access Control feature is disabled. Resource access is not revoked.");
            listener.onFailure(
                new OpenSearchException(
                    "Resource Access Control feature is disabled. Resource access is not revoked.",
                    RestStatus.NOT_IMPLEMENTED
                )
            );
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

    private ActionListener<ResourceAccessResponse> verifyAccessResponseListener(ActionListener<Boolean> listener) {
        return ActionListener.wrap(response -> listener.onResponse(response.getHasPermission()), listener::onFailure);
    }

    private ActionListener<ResourceAccessResponse> sharingInfoResponseListener(ActionListener<ResourceSharing> listener) {
        return ActionListener.wrap(response -> listener.onResponse(response.getResourceSharing()), listener::onFailure);
    }
}
