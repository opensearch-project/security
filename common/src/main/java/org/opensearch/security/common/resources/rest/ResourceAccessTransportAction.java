/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.common.resources.rest;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.common.resources.RecipientType;
import org.opensearch.security.common.resources.RecipientTypeRegistry;
import org.opensearch.security.common.resources.ResourceAccessHandler;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class ResourceAccessTransportAction extends HandledTransportAction<ResourceAccessRequest, ResourceAccessResponse> {
    private final ResourceAccessHandler resourceAccessHandler;

    @Inject
    public ResourceAccessTransportAction(
        TransportService transportService,
        ActionFilters actionFilters,
        ResourceAccessHandler resourceAccessHandler
    ) {
        super(ResourceAccessAction.NAME, transportService, actionFilters, ResourceAccessRequest::new);
        this.resourceAccessHandler = resourceAccessHandler;
    }

    @Override
    protected void doExecute(Task task, ResourceAccessRequest request, ActionListener<ResourceAccessResponse> actionListener) {
        switch (request.getOperation()) {
            case LIST:
                handleListResources(request, actionListener);
                break;
            case SHARE:
                handleGrantAccess(request, actionListener);
                break;
            case REVOKE:
                handleRevokeAccess(request, actionListener);
                break;
            case VERIFY:
                handleVerifyAccess(request, actionListener);
                break;
            default:
                actionListener.onFailure(new IllegalArgumentException("Unknown action type: " + request.getOperation()));
        }
    }

    private void handleListResources(ResourceAccessRequest request, ActionListener<ResourceAccessResponse> listener) {
        resourceAccessHandler.getAccessibleResourcesForCurrentUser(
            request.getResourceIndex(),
            ActionListener.wrap(resources -> listener.onResponse(new ResourceAccessResponse(resources)), listener::onFailure)
        );
    }

    private void handleGrantAccess(ResourceAccessRequest request, ActionListener<ResourceAccessResponse> listener) {
        resourceAccessHandler.shareWith(
            request.getResourceId(),
            request.getResourceIndex(),
            request.getShareWith(),
            ActionListener.wrap(response -> listener.onResponse(new ResourceAccessResponse(response)), listener::onFailure)
        );
    }

    private void handleRevokeAccess(ResourceAccessRequest request, ActionListener<ResourceAccessResponse> listener) {
        resourceAccessHandler.revokeAccess(
            request.getResourceId(),
            request.getResourceIndex(),
            parseRevokedEntities(request.getRevokedEntities()),
            request.getScopes(),
            ActionListener.wrap(success -> listener.onResponse(new ResourceAccessResponse(success)), listener::onFailure)
        );
    }

    private void handleVerifyAccess(ResourceAccessRequest request, ActionListener<ResourceAccessResponse> listener) {
        resourceAccessHandler.hasPermission(
            request.getResourceId(),
            request.getResourceIndex(),
            request.getScope(),
            ActionListener.wrap(hasPermission -> listener.onResponse(new ResourceAccessResponse(hasPermission)), listener::onFailure)
        );
    }

    /**
     * Helper method to parse revoked entities from a generic Map
     */
    private Map<RecipientType, Set<String>> parseRevokedEntities(Map<String, Set<String>> revokeSource) {
        return revokeSource.entrySet()
            .stream()
            .collect(Collectors.toMap(entry -> RecipientTypeRegistry.fromValue(entry.getKey()), Map.Entry::getValue));
    }
}
