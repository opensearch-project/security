/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.transport;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.indices.SystemIndices;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.rest.revoke.RevokeResourceAccessAction;
import org.opensearch.security.resources.rest.revoke.RevokeResourceAccessRequest;
import org.opensearch.security.resources.rest.revoke.RevokeResourceAccessResponse;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

/**
 * Transport action for handling resource access requests.
 *
 * @opensearch.experimental
 */
public class RevokeResourceAccessTransportAction extends HandledTransportAction<RevokeResourceAccessRequest, RevokeResourceAccessResponse> {
    private final ResourceAccessHandler resourceAccessHandler;

    private final SystemIndices systemIndices;

    @Inject
    public RevokeResourceAccessTransportAction(
        TransportService transportService,
        ActionFilters actionFilters,
        SystemIndices systemIndices,
        ResourceAccessHandler resourceAccessHandler
    ) {
        super(RevokeResourceAccessAction.NAME, transportService, actionFilters, RevokeResourceAccessRequest::new);
        this.systemIndices = systemIndices;
        this.resourceAccessHandler = resourceAccessHandler;
    }

    @Override
    protected void doExecute(Task task, RevokeResourceAccessRequest request, ActionListener<RevokeResourceAccessResponse> actionListener) {
        // verify that the request is for a system index
        if (!this.systemIndices.isSystemIndex(request.getResourceIndex())) {
            actionListener.onFailure(
                new OpenSearchStatusException(
                    "Resource index '" + request.getResourceIndex() + "' is not a system index.",
                    RestStatus.BAD_REQUEST
                )
            );
            return;
        }

        handleRevokeAccess(request, actionListener);

    }

    private void handleRevokeAccess(RevokeResourceAccessRequest request, ActionListener<RevokeResourceAccessResponse> listener) {
        resourceAccessHandler.revokeAccess(
            request.getResourceId(),
            request.getResourceIndex(),
            parseRevokedEntities(request.getRevokedEntities()),
            request.getActionGroups(),
            ActionListener.wrap(success -> listener.onResponse(new RevokeResourceAccessResponse(success)), listener::onFailure)
        );
    }

    private Map<Recipient, Set<String>> parseRevokedEntities(Map<String, Set<String>> revokeSource) {
        return revokeSource.entrySet()
            .stream()
            .collect(Collectors.toMap(entry -> Recipient.fromValue(entry.getKey()), Map.Entry::getValue));
    }
}
